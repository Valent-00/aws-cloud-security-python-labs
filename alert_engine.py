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
# Module-level constants
# These values are fixed for every scan run and do not vary per file,
# so they remain here rather than being baked into the function body.
# ---------------------------------------------------------------------------

ALERT_DIR    = "active_tickets"              # Output directory for tickets
ALERT_FILE   = f"{ALERT_DIR}/live_alert.json"   # Output alert filepath
TARGET_EVENT = "StopLogging"                # API call that triggers the alert


# ---------------------------------------------------------------------------
# Core engine function
# ---------------------------------------------------------------------------

def analyze_log_file(filepath: str) -> None:
    """
    Scan a CloudTrail JSON log file for Defense Evasion activity and
    raise an alert if a "StopLogging" event is detected.

    Why `filepath` is a parameter rather than a hardcoded constant
    ---------------------------------------------------------------
    Accepting `filepath` as a dynamic argument decouples the engine's
    detection logic from any single, fixed file location. The same
    function can therefore be called multiple times in one run — or
    from any external orchestrator — to scan completely different log
    sources without touching the function body:

        analyze_log_file("logs_dataset_source.json")
        analyze_log_file("../telemetry_lab/logs_dataset_source.json")
        analyze_log_file("/var/log/cloudtrail/prod_2026_06.json")

    Each call is fully independent; the function reads only the file
    it was told about via `filepath`.

    Args:
        filepath: Path (relative or absolute) to the CloudTrail JSON
                  log file to be scanned.

    Returns:
        None. Side effects are a terminal alert and a written ticket
        file when a threat is found.
    """

    try:
        # ── 1. LOAD ─────────────────────────────────────────────────────────
        # `filepath` — the parameter — is used here directly, so the
        # function opens whichever file the caller specified.
        with open(filepath, "r", encoding="utf-8") as log_file:
            events = json.load(log_file)   # Deserialise JSON array → Python list

        # ── 2. SCAN ─────────────────────────────────────────────────────────
        # Iterate through every event dictionary in the log list.
        for event in events:

            # Check whether this event represents a StopLogging API call.
            if event["eventName"] == TARGET_EVENT:

                # ── 3. TERMINAL ALERT ───────────────────────────────────────
                # Immediately surface the detection to the operator's console.
                print("[ALERT] Defense Evasion Detected!")

                # ── 4. BUILD INCIDENT RECORD ────────────────────────────────
                # Extract the three key forensic fields needed for the ticket.
                # `userIdentity` is a nested dict, so we chain two key lookups.
                incident = {
                    "alert_type":   "Defense Evasion — StopLogging",
                    "event_time":   event["eventTime"],
                    "source_ip":    event["sourceIPAddress"],
                    "user":         event["userIdentity"]["userName"]
                }

                # ── 5. PERSIST ALERT ────────────────────────────────────────
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
        # `filepath` is used here too, so the error message always names
        # the exact file path the caller passed in — not a stale constant.
        print(f"[ERROR] Source log file not found: '{filepath}'")
        print("        Ensure 'generate_mock_telemetry.py' has been run first.")


# ---------------------------------------------------------------------------
# Entry point
# Passing "logs_dataset_source.json" as the filepath argument demonstrates
# how the function is called. Swapping this string for any other path would
# redirect the entire scan to a different file with zero code changes inside
# the function itself.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    analyze_log_file("telemetry_lab/logs_dataset_source.json")