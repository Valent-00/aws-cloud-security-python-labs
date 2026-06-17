"""
alert_engine.py
---------------
Scans a CloudTrail log dataset for Defense Evasion activity.
Specifically, it watches for any "StopLogging" API call — an attacker
technique used to disable audit trails and blind security teams.

When the threat event is detected, the engine:
    1. Prints a real-time ALERT to the terminal.
    2. Extracts the key forensic fields from the event.
    3. Saves a structured alert record to `active_tickets/live_alert.json`.

Libraries:
    json  — native deserialisation and serialisation
    os    — safe directory creation

Usage:
    python alert_engine.py
"""

import json
import os


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_FILE   = "../telemetry_lab/logs_dataset_source.json"   # Input log dataset
ALERT_DIR     = "active_tickets"             # Output directory for tickets
ALERT_FILE    = f"{ALERT_DIR}/live_alert.json"  # Output alert filepath
TARGET_EVENT  = "StopLogging"               # API call that triggers the alert


# ---------------------------------------------------------------------------
# Main scanning logic
# ---------------------------------------------------------------------------

try:
    # ── 1. LOAD ─────────────────────────────────────────────────────────────
    # Open the log source file with a context manager so the handle is
    # always closed cleanly after json.load() completes.
    with open(SOURCE_FILE, "r", encoding="utf-8") as log_file:
        events = json.load(log_file)   # Deserialise JSON array → Python list

    # ── 2. SCAN ─────────────────────────────────────────────────────────────
    # Iterate through every event dictionary in the log list.
    for event in events:

        # Check whether this event represents a StopLogging API call.
        if event["eventName"] == TARGET_EVENT:

            # ── 3. TERMINAL ALERT ───────────────────────────────────────────
            # Immediately surface the detection to the operator's console.
            print("[ALERT] Defense Evasion Detected!")

            # ── 4. BUILD INCIDENT RECORD ────────────────────────────────────
            # Extract the three key forensic fields needed for the ticket.
            # `userIdentity` is a nested dict, so we chain two key lookups.
            incident = {
                "alert_type":   "Defense Evasion — StopLogging",
                "event_time":   event["eventTime"],
                "source_ip":    event["sourceIPAddress"],
                "user":         event["userIdentity"]["userName"]
            }

            # ── 5. PERSIST ALERT ────────────────────────────────────────────
            # Safely create the output directory (no-op if already present).
            os.makedirs(ALERT_DIR, exist_ok=True)

            # Write the incident dictionary to disk as formatted JSON.
            with open(ALERT_FILE, "w", encoding="utf-8") as alert_file:
                json.dump(incident, alert_file, indent=4)

            print(f"         Event Time : {incident['event_time']}")
            print(f"         Source IP  : {incident['source_ip']}")
            print(f"         User       : {incident['user']}")
            print(f"[SAVED]  Alert ticket written to '{ALERT_FILE}'")

except FileNotFoundError:
    # Raised when the OS cannot locate `logs_dataset_source.json`.
    print(f"[ERROR] Source log file not found: '{SOURCE_FILE}'")
    print("        Ensure 'generate_mock_telemetry.py' has been run first.")