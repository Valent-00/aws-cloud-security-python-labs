"""
generate_mock_telemetry.py
--------------------------
Generates a simulated AWS CloudTrail JSON log file (`logs_dataset_source.json`)
containing 5 structured event dictionaries that map out a realistic multi-stage
attack timeline against a cloud environment.

Attack Stages Modelled:
    0. Normal baseline activity (legitimate staff user)
    1. Initial Access   — Console login from an external threat actor IP
    2. Discovery        — Enumerate EC2 instances to map the environment
    3. Persistence      — Create a backdoor IAM user for long-term access
    4. Defense Evasion  — Disable CloudTrail logging to blind defenders

Output:
    logs_dataset_source.json — Human-readable JSON (4-space indentation)

Usage:
    python generate_mock_telemetry.py
"""

import json


# ---------------------------------------------------------------------------
# 1. DATASET DEFINITION — 5 CloudTrail-structured event dictionaries
# ---------------------------------------------------------------------------

# Each event mirrors the AWS CloudTrail record schema with the 5 required keys:
#   - eventTime        : ISO-8601 UTC timestamp of the event
#   - eventName        : AWS API action that was called
#   - sourceIPAddress  : Originating IP address of the request
#   - userIdentity     : Dict carrying the principal who made the call
#   - errorCode        : AWS error code if the call failed; "None" if successful

cloudtrail_events = [
    # ------------------------------------------------------------------
    # Event 0 — NORMAL ACTIVITY
    # Legitimate staff performing routine EC2 describe (read-only) action.
    # ------------------------------------------------------------------
    {
        "eventTime":       "2025-06-01T08:15:00Z",
        "eventName":       "DescribeInstances",
        "sourceIPAddress": "192.168.1.45",
        "userIdentity":    {
            "type":     "IAMUser",
            "userName": "valent_staff"
        },
        "errorCode":       "None"
    },

    # ------------------------------------------------------------------
    # Event 1 — ATTACK STEP 1: INITIAL ACCESS
    # Threat actor authenticates via the AWS Management Console using
    # a compromised administrative credential from an external IP.
    # ------------------------------------------------------------------
    {
        "eventTime":       "2025-06-01T09:02:34Z",
        "eventName":       "ConsoleLogin",
        "sourceIPAddress": "203.0.113.115",
        "userIdentity":    {
            "type":     "IAMUser",
            "userName": "compromised_admin"
        },
        "errorCode":       "None"
    },

    # ------------------------------------------------------------------
    # Event 2 — ATTACK STEP 2: DISCOVERY
    # Attacker enumerates all EC2 instances to map the victim's
    # infrastructure and identify high-value targets.
    # ------------------------------------------------------------------
    {
        "eventTime":       "2025-06-01T09:05:11Z",
        "eventName":       "DescribeInstances",
        "sourceIPAddress": "203.0.113.115",
        "userIdentity":    {
            "type":     "IAMUser",
            "userName": "compromised_admin"
        },
        "errorCode":       "None"
    },

    # ------------------------------------------------------------------
    # Event 3 — ATTACK STEP 3: PERSISTENCE
    # Attacker creates a new IAM user as a backdoor, ensuring continued
    # access even if the original compromised credentials are revoked.
    # ------------------------------------------------------------------
    {
        "eventTime":       "2025-06-01T09:12:47Z",
        "eventName":       "CreateUser",
        "sourceIPAddress": "203.0.113.115",
        "userIdentity":    {
            "type":     "IAMUser",
            "userName": "compromised_admin"
        },
        "errorCode":       "None"
    },

    # ------------------------------------------------------------------
    # Event 4 — ATTACK STEP 4: DEFENSE EVASION
    # Attacker disables CloudTrail logging to erase the activity trail
    # and prevent further detection of malicious operations.
    # ------------------------------------------------------------------
    {
        "eventTime":       "2025-06-01T09:18:05Z",
        "eventName":       "StopLogging",
        "sourceIPAddress": "203.0.113.115",
        "userIdentity":    {
            "type":     "IAMUser",
            "userName": "compromised_admin"
        },
        "errorCode":       "None"
    }
]


# ---------------------------------------------------------------------------
# 2. FILE GENERATION — Write dataset to JSON using a context manager
# ---------------------------------------------------------------------------

# Destination filename for the generated CloudTrail log dataset
OUTPUT_FILENAME = "logs_dataset_source.json"

# Open the file in write mode using a context manager to guarantee the file
# handle is properly closed even if an exception occurs during serialisation.
with open(OUTPUT_FILENAME, "w", encoding="utf-8") as output_file:
    # json.dump serialises the Python list directly to the file object.
    # indent=4 produces human-readable, 4-space indented output.
    # ensure_ascii=False preserves any non-ASCII characters if present.
    json.dump(cloudtrail_events, output_file, indent=4, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 3. CONFIRMATION — Inform the operator that generation succeeded
# ---------------------------------------------------------------------------

print(f"[SUCCESS] Mock CloudTrail telemetry dataset written to '{OUTPUT_FILENAME}'")
print(f"          Total events serialised: {len(cloudtrail_events)}")