"""
api_mock_scanner.py
--------------------
Enterprise-grade IAM Compliance, Configuration Drift & Risk-Scoring Scanner.
Modernized for the current Google GenAI SDK.
"""

import os
import time
import json
import logging
# [MODERNIZED] Import the updated unified genai package
from google import genai
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Pathing, Logging & API Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "scanner_operations.log")
STATE_FILE_PATH = os.path.join(SCRIPT_DIR, "state", "baseline_iam.json")

os.makedirs(os.path.dirname(STATE_FILE_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH),
        logging.StreamHandler()
    ]
)

# Securely load the API key from the .env file
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# [MODERNIZED] Initialize the modern Client object
client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        logging.error(f"Failed to initialize Gemini Client: {e}")
else:
    logging.warning("No GEMINI_API_KEY found in .env file. Live API will fallback.")

# ---------------------------------------------------------------------------
# Risk Scoring Constants
# ---------------------------------------------------------------------------
RISK_BASE_SCORES = {
    "MFA Disabled": 50,
    "New User Created": 40,
    "Stale Key": 20,
    "Role Changed": 60,
}
KEY_ROTATION_LIMIT_DAYS = 90
ADMIN_ROLE_MULTIPLIER = 1.5
MAX_RISK_SCORE = 99

# ---------------------------------------------------------------------------
# 1. Data Provider Layer
# ---------------------------------------------------------------------------
def fetch_cloud_inventory():
    """Simulates fetching live data from AWS IAM."""
    logging.info("Connecting to AWS IAM Global Endpoint...")
    time.sleep(1)

    return [
        {"username": "admin_root", "mfa_enabled": False, "key_age_days": 115, "role": "Administrator"},
        {"username": "intern_dev01", "mfa_enabled": False, "key_age_days": 12, "role": "Developer"},
        {"username": "contractor_sec", "mfa_enabled": False, "key_age_days": 45, "role": "SecurityAuditor"},
        {"username": "stale_deployer", "mfa_enabled": False, "key_age_days": 210, "role": "DevOps"}
    ]

# ---------------------------------------------------------------------------
# 2. Risk Scoring Engine
# ---------------------------------------------------------------------------
def calculate_risk_score(incident_type, user_role, key_age=0):
    score = RISK_BASE_SCORES.get(incident_type, 0)
    if incident_type == "Stale Key" and key_age > KEY_ROTATION_LIMIT_DAYS:
        score += (key_age - KEY_ROTATION_LIMIT_DAYS)
    if user_role == "Administrator":
        score *= ADMIN_ROLE_MULTIPLIER
    return min(round(score), MAX_RISK_SCORE)

# ---------------------------------------------------------------------------
# 3. STATEFUL MEMORY: Configuration Drift Engine
# ---------------------------------------------------------------------------
def detect_configuration_drift(current_data):
    if not os.path.exists(STATE_FILE_PATH):
        logging.info("No baseline found. Establishing initial security baseline...")
        with open(STATE_FILE_PATH, 'w') as f:
            json.dump(current_data, f, indent=4)
        return []

    with open(STATE_FILE_PATH, 'r') as f:
        baseline_data = json.load(f)

    baseline_dict = {user["username"]: user for user in baseline_data}
    drift_alerts = []

    logging.info("Comparing current environment against established baseline...")

    for current_user in current_data:
        username = current_user["username"]
        current_role = current_user["role"]

        if username not in baseline_dict:
            logging.critical(f"DRIFT DETECTED: Unauthorized creation of new user '{username}'")
            drift_alerts.append({
                "username": username,
                "alert_type": "New User Created",
                "risk_score": calculate_risk_score("New User Created", current_role),
            })
            continue

        past_user = baseline_dict[username]

        if past_user["mfa_enabled"] is True and current_user["mfa_enabled"] is False:
            logging.critical(f"DRIFT DETECTED: {username} disabled their MFA!")
            drift_alerts.append({
                "username": username,
                "alert_type": "MFA Disabled",
                "risk_score": calculate_risk_score("MFA Disabled", current_role),
            })

        if past_user["role"] != current_user["role"]:
            logging.critical(f"DRIFT DETECTED: Privilege Escalation! {username} changed role")
            drift_alerts.append({
                "username": username,
                "alert_type": "Role Changed",
                "risk_score": calculate_risk_score("Role Changed", current_role),
                "details": f"{past_user['role']} -> {current_user['role']}",
            })

    with open(STATE_FILE_PATH, 'w') as f:
        json.dump(current_data, f, indent=4)

    return drift_alerts

# ---------------------------------------------------------------------------
# 4. Standard Compliance Engine
# ---------------------------------------------------------------------------
def scan_iam_posture(users_list):
    findings = []
    for user in users_list:
        username = user["username"]
        role = user["role"]

        if user["mfa_enabled"] is False:
            findings.append({
                "username": username,
                "alert_type": "MFA Disabled",
                "risk_score": calculate_risk_score("MFA Disabled", role),
            })

        if user["key_age_days"] > KEY_ROTATION_LIMIT_DAYS:
            findings.append({
                "username": username,
                "alert_type": "Stale Key",
                "risk_score": calculate_risk_score("Stale Key", role, key_age=user["key_age_days"]),
                "details": f"{user['key_age_days']} days old",
            })
    return findings

# ---------------------------------------------------------------------------
# 5. Generative AI Incident Summarization (Fault-Tolerant)
# ---------------------------------------------------------------------------
def generate_ai_summary(findings):
    """Filters high-risk alerts and generates an executive report with fallback handling."""
    high_risk_alerts = [alert for alert in findings if alert.get("risk_score", 0) >= 70]
    
    if not high_risk_alerts:
        logging.info("No critical incidents (Risk 70+) require AI summarization.")
        return

    # Helper nested function for clean execution of our static local reporting fallback
    def trigger_local_fallback(reason):
        logging.warning(f"{reason} Activating Local Rule-Based Fallback Engine...")
        print("\n" + "="*80)
        print(" 🛡️ EXECUTIVE MITIGATION REPORT (LOCAL PLATFORM FALLBACK)")
        print("="*80)
        print("CRITICAL ENVIRONMENT ANALYSIS SUMMARY:")
        print(f"The automated audit pipeline has intercepted {len(high_risk_alerts)} critical risk vectors.")
        print("\nIDENTIFIED THREATS & BUSINESS IMPACT:")
        
        for alert in high_risk_alerts:
            print(f"\n -> [RISK SCORE: {alert['risk_score']}] Target Account: {alert['username']}")
            print(f"    Violation: {alert['alert_type']}")
            if alert['alert_type'] == "MFA Disabled":
                print("    Impact   : Severe threat of unauthorized credential abuse, session hijacking, and persistent cloud backdoor placement.")
                print("    Action   : Enforce Multi-Factor Authentication immediately and revoke active console sessions.")
            elif "Stale Key" in alert['alert_type']:
                print("    Impact   : Stale static access keys expand credential leak windows and programmatic compromise vectors.")
                print("    Action   : Trigger mandatory credential rotation and update associated pipeline injection points.")
        print("\n" + "="*80 + "\n")

    # If the modern client wasn't successfully instantiated, trigger fallback immediately
    if not client:
        trigger_local_fallback("Modern Gemini Client uninitialized.")
        return

    logging.info(f"Escalating {len(high_risk_alerts)} critical alerts to AI SOC Analyst...")
    alert_payload = json.dumps(high_risk_alerts, indent=2)
    
    prompt = f"""
    Act as a Lead Cloud Security SOC Analyst. Review the following JSON security alerts.
    Write a short, professional "Executive Incident Mitigation Report" for management.
    Explain the business risk of these specific vulnerabilities and provide bulleted, actionable remediation steps.
    Do not output JSON, output a clean, formatted text report. Keep it concise.
    
    ALERTS:
    {alert_payload}
    """

    # [MODERNIZED] Unified API method call layout
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt,
        )
        
        print("\n" + "="*80)
        print(" 🤖 AI-GENERATED EXECUTIVE MITIGATION REPORT (LIVE API)")
        print("="*80)
        print(response.text.strip())
        print("="*80 + "\n")
        
    except Exception as e:
        if "429" in str(e) or "quota" in str(e).lower():
            trigger_local_fallback("Gemini API Rate Limit Exceeded (429).")
        else:
            logging.error(f"AI Generation Failed due to unexpected exception: {e}")

# ---------------------------------------------------------------------------
# Pipeline Execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "="*60)
    print(" 🛡️ SOC COMPLIANCE & DRIFT SCANNER INITIALIZING...")
    print("="*60)

    iam_data = fetch_cloud_inventory()

    if iam_data:
        drift_findings = detect_configuration_drift(iam_data)
        security_findings = scan_iam_posture(iam_data)

        master_incident_queue = drift_findings + security_findings
        
        # Remove duplicate records for the AI processing funnel
        unique_queue = []
        seen = set()
        for d in master_incident_queue:
            t = tuple(d.items())
            if t not in seen:
                seen.add(t)
                unique_queue.append(d)

        unique_queue.sort(key=lambda alert: alert["risk_score"], reverse=True)

        print("\n" + "="*60)
        print(" 🚨 PRIORITIZED SOC INCIDENT QUEUE")
        print("="*60)
        if unique_queue:
            for alert in unique_queue:
                print(f" [Risk: {alert['risk_score']:>2}] {alert['username']} - {alert['alert_type']}")
        else:
            print(" No incidents detected. Environment is clean.")
        print("="*60)
        
        # Execute Engine Funnel
        generate_ai_summary(unique_queue)