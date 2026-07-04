#!/bin/bash
# =============================================================================
# deploy.sh
# Packages and deploys the IAM Security Scanner to AWS Lambda.
# Sets up EventBridge to trigger it automatically every 24 hours.
#
# Prerequisites
# -------------
#   1. AWS CLI installed: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
#   2. AWS CLI configured: aws configure  (use your IAM admin credentials)
#   3. Fill in the CONFIGURATION section below before running
#   4. chmod +x deploy.sh && ./deploy.sh
#
# What this script does
# ----------------------
#   1. Creates the S3 bucket for scan reports (if it doesn't exist)
#   2. Creates the Lambda execution role with least-privilege IAM policy
#   3. Packages your scanner code into a zip (no bundling boto3 — already in runtime)
#   4. Creates or updates the Lambda function
#   5. Creates an EventBridge rule to trigger it daily
#   6. Runs a test invocation so you can see the first real scan result
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION — fill these in before running
# =============================================================================
AWS_ACCOUNT_ID="501421114742"          # e.g. 123456789012
AWS_REGION="ap-southeast-2"                   # change to your region
FUNCTION_NAME="iam-security-scanner"
ROLE_NAME="iam-scanner-execution-role"
REPORT_BUCKET="${AWS_ACCOUNT_ID}-iam-scanner-reports"   # must be globally unique
RUNTIME="python3.12"
TIMEOUT=300                                   # 5 minutes
MEMORY=256                                    # MB

# Third-party packages your Lambda code imports that AREN'T part of the
# managed runtime (which only ships boto3/botocore + stdlib). Add to this
# list any time you get "No module named 'X'" from the test invocation.
LAMBDA_DEPENDENCIES=("requests" "python-dotenv")

# Scanner thresholds — adjust to your organisation's security policy
KEY_ROTATION_DAYS=90
PASSWORD_MAX_AGE_DAYS=90
STALE_ACCOUNT_DAYS=60
DORMANT_ADMIN_DAYS=30
MAX_ACTIVE_KEYS_PER_USER=1

# Real-time alerting — optional. Leave blank to skip; notifications.py
# only sends if Critical/High findings exist AND the relevant URL is
# set, so leaving these empty is a safe, fully-supported default.
#
# Slack: create a Slack App -> Incoming Webhooks -> Add New Webhook to
#   Workspace. URL looks like https://hooks.slack.com/services/...
#
# Teams: classic "Incoming Webhook" connectors were retired in
#   Microsoft's May 2026 rollout and no longer work. Use a channel's
#   Workflows tab instead -> search "webhook" -> "Post to a channel
#   when a webhook request is received" template. URL looks like
#   https://...powerautomate.com/... or https://...flow.microsoft.com/...
#
# Treat both URLs as secrets — anyone who has one can post into that
# channel. Set via your shell environment, not hardcoded here, if this
# script is ever committed anywhere.
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
TEAMS_WEBHOOK_URL="${TEAMS_WEBHOOK_URL:-}"
DASHBOARD_URL="${DASHBOARD_URL:-}"          # optional link included in alerts
# =============================================================================

echo ""
echo "======================================================"
echo "  IAM Security Scanner — Deployment Script"
echo "  Account: $AWS_ACCOUNT_ID | Region: $AWS_REGION"
echo "======================================================"
echo ""

# ---------------------------------------------------------------------------
# Step 0 — Resolve a working Python interpreter
# ---------------------------------------------------------------------------
# We can't hardcode `python3`: the official python.org Windows installer
# only provides `python` (and `py`), not `python3`. On a stock Windows box
# with no real Python on PATH, `python3.exe` actually resolves to a
# non-functional Windows "App execution alias" stub in WindowsApps, which
# prints "Python was not found; run without arguments to install from the
# Microsoft Store..." instead of failing like a normal missing command.
# `command -v` would report that stub as "found", so we have to actually
# invoke each candidate and check it behaves like real Python.
PYTHON_BIN=""
for candidate in python3 python "py -3"; do
    if $candidate -c "import sys" > /dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: no working Python interpreter found (tried: python3, python, py -3)." >&2
    echo "Install Python from https://python.org/downloads and ensure it's on PATH," >&2
    echo "or disable the python3/python App execution aliases in" >&2
    echo "Settings > Apps > Advanced app settings > App execution aliases." >&2
    exit 1
fi
echo "    Using Python interpreter: $PYTHON_BIN"

# Native Windows tools (aws.exe, python.exe, etc.) only reliably get a
# correctly-translated path from Git Bash when that path is its own clean
# argv token. Once a path is embedded *inside* a longer string — a
# PowerShell -Command body (the Step 3 bug from earlier) or a fileb://
# URI (the Step 4 bug below) — Git Bash's automatic POSIX-to-Windows
# path conversion doesn't reliably catch it, and the native tool receives
# a raw "/c/Users/..." string it has no idea how to resolve. We sidestep
# this permanently by converting explicitly with cygpath wherever a path
# gets embedded in a composite argument.
to_win_path() {
    if command -v cygpath > /dev/null 2>&1; then
        cygpath -m "$1"
    else
        printf '%s' "$1"
    fi
}
echo ""

# ---------------------------------------------------------------------------
# Step 1 — Create S3 bucket for reports
# ---------------------------------------------------------------------------
echo "--> Step 1/6: Creating S3 report bucket..."

if aws s3api head-bucket --bucket "$REPORT_BUCKET" --region "$AWS_REGION" 2>/dev/null; then
    echo "    Bucket already exists: s3://$REPORT_BUCKET"
else
    if [ "$AWS_REGION" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "$REPORT_BUCKET" \
            --region "$AWS_REGION" > /dev/null
    else
        aws s3api create-bucket \
            --bucket "$REPORT_BUCKET" \
            --region "$AWS_REGION" \
            --create-bucket-configuration LocationConstraint="$AWS_REGION" > /dev/null
    fi

    # Block all public access — reports contain security findings
    aws s3api put-public-access-block \
        --bucket "$REPORT_BUCKET" \
        --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" > /dev/null

    # Enable versioning for audit trail
    aws s3api put-bucket-versioning \
        --bucket "$REPORT_BUCKET" \
        --versioning-configuration Status=Enabled > /dev/null

    echo "    Created: s3://$REPORT_BUCKET (public access blocked, versioning on)"
fi

# ---------------------------------------------------------------------------
# Step 2 — Create Lambda execution role
# ---------------------------------------------------------------------------
echo ""
echo "--> Step 2/6: Creating Lambda execution role..."

TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

if aws iam get-role --role-name "$ROLE_NAME" > /dev/null 2>&1; then
    echo "    Role already exists: $ROLE_NAME"
else
    aws iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document "$TRUST_POLICY" \
        --description "Least-privilege execution role for IAM Security Scanner Lambda" \
        --output text --query 'Role.Arn' > /dev/null
    echo "    Role created: $ROLE_NAME"
fi

# Substitute the real bucket name into the policy file
POLICY_JSON=$(sed "s/REPLACE_WITH_YOUR_BUCKET_NAME/$REPORT_BUCKET/" iam_execution_role.json)

# Attach the inline policy
aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "iam-scanner-policy" \
    --policy-document "$POLICY_JSON" > /dev/null

ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"
echo "    Policy attached. Role ARN: $ROLE_ARN"

# ---------------------------------------------------------------------------
# Step 3 — Package the Lambda deployment zip
# ---------------------------------------------------------------------------
echo ""
echo "--> Step 3/6: Packaging deployment zip..."

PACKAGE_DIR="$PWD/build/iam_scanner_lambda_pkg"
ZIP_PATH="$PWD/build/iam_scanner_lambda.zip"

mkdir -p "$PWD/build"

rm -rf "$PACKAGE_DIR" "$ZIP_PATH"
mkdir -p "$PACKAGE_DIR/shared"

# Copy Lambda entry point and boto3 inventory fetcher
cp lambda_function.py "$PACKAGE_DIR/"
cp ../shared/*.py "$PACKAGE_DIR/shared/"

# Copy your ACTUAL scanner — no modifications needed

# boto3 is pre-installed in the Lambda Python 3.12 runtime — do NOT bundle it.
# Everything else in $LAMBDA_DEPENDENCIES has to be vendored into the
# package directory, since Lambda's filesystem is read-only and has no
# pip available at runtime.
if [ ${#LAMBDA_DEPENDENCIES[@]} -gt 0 ]; then
    echo "    Installing Lambda dependencies: ${LAMBDA_DEPENDENCIES[*]}"
    PYVER="${RUNTIME#python}"   # "python3.12" -> "3.12"

    # We're on Windows, packaging for Lambda's Linux runtime. Without
    # --platform/--only-binary, pip would happily install whatever wheel
    # matches *this* machine (Windows) for any dependency that ships
    # compiled extensions, which would then fail to import in Lambda with
    # an unhelpful error. requests itself is pure Python either way, but
    # pinning the target platform makes this safe for whatever you add
    # to LAMBDA_DEPENDENCIES later, too. We call pip via $PYTHON_BIN -m pip
    # rather than a bare `pip` so it's guaranteed to be the same
    # interpreter we already verified works (a bare `pip` on PATH could
    # silently resolve to a different Python install).
    $PYTHON_BIN -m pip install "${LAMBDA_DEPENDENCIES[@]}" \
        --target "$PACKAGE_DIR" \
        --platform manylinux2014_x86_64 \
        --only-binary=:all: \
        --python-version "$PYVER" \
        --implementation cp \
        --quiet
fi

# Create the zip with Python's stdlib zipfile module. We deliberately avoid
# shelling out to `zip` or `powershell.exe Compress-Archive`:
#   - `zip` isn't reliably present on a stock Windows + Git Bash setup
#   - Compress-Archive, when called from Git Bash, is fed MSYS-translated
#     paths (e.g. "/c/Users/..." -> "\c\Users\...") that drop the drive
#     colon, which is exactly the ArchiveCmdletPathNotFound error you hit.
# Walking PACKAGE_DIR in Python and writing relative arcnames also removes
# the need to cd into PACKAGE_DIR first (and cd back out afterward), so
# the zip root contains lambda_function.py / boto3_inventory.py / scanner/
# directly — not the whole project tree.
$PYTHON_BIN - "$PACKAGE_DIR" "$ZIP_PATH" <<'PYEOF'
import os
import sys
import zipfile

src_dir, zip_path = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for filename in files:
            if filename.endswith((".pyc", ".log")):
                continue
            full_path = os.path.join(root, filename)
            arcname = os.path.relpath(full_path, src_dir)
            zf.write(full_path, arcname)
print(f"Packaged {zip_path}")
PYEOF

ZIPSIZE=$(du -sh "$ZIP_PATH" | cut -f1)
echo "    Package size: $ZIPSIZE -> $ZIP_PATH"

# Build the --zip-file URI from a Windows-native path. This is what was
# actually failing in Step 4: "fileb://$ZIP_PATH" embeds the raw MSYS
# "/c/Users/..." path inside the URI string, and aws.exe's Python runtime
# tried to open that literal path with Windows' file APIs, which don't
# understand it — hence "No such file or directory" even though the zip
# was sitting right there on disk.
ZIP_FILE_URI="fileb://$(to_win_path "$ZIP_PATH")"

# ---------------------------------------------------------------------------
# Step 4 — Create or update the Lambda function
# ---------------------------------------------------------------------------
echo ""
echo "--> Step 4/6: Deploying Lambda function..."

# Give IAM role time to propagate (AWS eventual consistency)
echo "    Waiting 10s for IAM role propagation..."
sleep 10

ENV_VARS="Variables={
    REPORT_BUCKET=$REPORT_BUCKET,
    KEY_ROTATION_DAYS=$KEY_ROTATION_DAYS,
    PASSWORD_MAX_AGE_DAYS=$PASSWORD_MAX_AGE_DAYS,
    STALE_ACCOUNT_DAYS=$STALE_ACCOUNT_DAYS,
    DORMANT_ADMIN_DAYS=$DORMANT_ADMIN_DAYS,
    MAX_ACTIVE_KEYS_PER_USER=$MAX_ACTIVE_KEYS_PER_USER,
    LOG_LEVEL=INFO,
    SCANNER_LOG_TO_FILE=false,
    SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL,
    TEAMS_WEBHOOK_URL=$TEAMS_WEBHOOK_URL,
    DASHBOARD_URL=$DASHBOARD_URL
}"

if aws lambda get-function \
    --function-name "$FUNCTION_NAME" \
    --region "$AWS_REGION" > /dev/null 2>&1; then

    echo "    Function exists — updating code..."
    aws lambda update-function-code \
        --function-name "$FUNCTION_NAME" \
        --zip-file "$ZIP_FILE_URI" \
        --region "$AWS_REGION" \
        --output text --query 'FunctionArn' > /dev/null

    aws lambda wait function-updated \
        --function-name "$FUNCTION_NAME" \
        --region "$AWS_REGION"

    aws lambda update-function-configuration \
        --function-name "$FUNCTION_NAME" \
        --timeout "$TIMEOUT" \
        --memory-size "$MEMORY" \
        --environment "$ENV_VARS" \
        --region "$AWS_REGION" \
        --output text --query 'FunctionArn' > /dev/null

else
    echo "    Creating new function..."
    aws lambda create-function \
        --function-name "$FUNCTION_NAME" \
        --runtime "$RUNTIME" \
        --role "$ROLE_ARN" \
        --handler "lambda_function.handler" \
        --zip-file "$ZIP_FILE_URI" \
        --timeout "$TIMEOUT" \
        --memory-size "$MEMORY" \
        --environment "$ENV_VARS" \
        --description "Scheduled IAM Security Posture Scanner" \
        --region "$AWS_REGION" \
        --output text --query 'FunctionArn' > /dev/null
fi

LAMBDA_ARN=$(aws lambda get-function \
    --function-name "$FUNCTION_NAME" \
    --region "$AWS_REGION" \
    --output text --query 'Configuration.FunctionArn')

echo "    Lambda ARN: $LAMBDA_ARN"

# ---------------------------------------------------------------------------
# Step 5 — EventBridge daily trigger
# ---------------------------------------------------------------------------
echo ""
echo "--> Step 5/6: Setting up EventBridge daily trigger..."

RULE_ARN=$(aws events put-rule \
    --name "iam-scanner-daily-trigger" \
    --schedule-expression "rate(1 day)" \
    --description "Triggers IAM Security Scanner every 24 hours" \
    --state ENABLED \
    --region "$AWS_REGION" \
    --output text --query 'RuleArn')

echo "    Rule ARN: $RULE_ARN"

# Grant EventBridge permission to invoke Lambda
aws lambda add-permission \
    --function-name "$FUNCTION_NAME" \
    --statement-id "EventBridgeDailyTrigger" \
    --action "lambda:InvokeFunction" \
    --principal "events.amazonaws.com" \
    --source-arn "$RULE_ARN" \
    --region "$AWS_REGION" \
    --output text > /dev/null 2>&1 || echo "    (Permission already exists — skipped)"

# Set Lambda as target
aws events put-targets \
    --rule "iam-scanner-daily-trigger" \
    --targets "[{\"Id\": \"iam-scanner-lambda\", \"Arn\": \"$LAMBDA_ARN\"}]" \
    --region "$AWS_REGION" \
    --output text > /dev/null

echo "    EventBridge trigger configured: rate(1 day)"

# ---------------------------------------------------------------------------
# Step 6 — Test invocation
# ---------------------------------------------------------------------------
echo ""
echo "--> Step 6/6: Running first test scan..."
echo "    This may take 30–120 seconds depending on account size."
echo ""

RESPONSE_FILE="/tmp/iam_scanner_test_response.json"

aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --region "$AWS_REGION" \
    --log-type Tail \
    --query 'LogResult' \
    --output text \
    "$RESPONSE_FILE" | base64 --decode 2>/dev/null | grep -E "INFO|WARNING|ERROR|CRITICAL|Scan complete" || true

echo ""
echo "    Test response:"
cat "$RESPONSE_FILE" | $PYTHON_BIN -m json.tool 2>/dev/null || cat "$RESPONSE_FILE"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================================"
echo "  DEPLOYMENT COMPLETE"
echo "======================================================"
echo ""
echo "  Function  : $FUNCTION_NAME"
echo "  Region    : $AWS_REGION"
echo "  Trigger   : Every 24 hours (EventBridge)"
echo "  Reports   : s3://$REPORT_BUCKET/scan_results/"
echo "  Logs      : CloudWatch → /aws/lambda/$FUNCTION_NAME"
echo ""
echo "  Useful commands:"
echo ""
echo "  View latest logs:"
echo "    aws logs tail /aws/lambda/$FUNCTION_NAME --follow --region $AWS_REGION"
echo ""
echo "  Manual scan:"
echo "    aws lambda invoke \\"
echo "      --function-name $FUNCTION_NAME \\"
echo "      --region $AWS_REGION \\"
echo "      /tmp/response.json && cat /tmp/response.json"
echo ""
echo "  View reports:"
echo "    aws s3 ls s3://$REPORT_BUCKET/scan_results/ --recursive --region $AWS_REGION"
echo ""
echo "  Download latest report:"
echo "    aws s3 cp s3://$REPORT_BUCKET/scan_results/ /tmp/reports/ --recursive --region $AWS_REGION"
echo "======================================================"
