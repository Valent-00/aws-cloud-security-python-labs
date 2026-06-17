"""
parse_logs.py
-------------
Reads the simulated AWS CloudTrail dataset (`logs_dataset_source.json`)
and prints a clean, human-readable event timeline to the terminal.

Demonstrates:
    - Native `json` library for deserialisation
    - `with open()` context manager for safe file I/O
    - `for` loop iteration over a list of event dictionaries
    - Nested key access  (`event["userIdentity"]["userName"]`)
    - `try/except` exception handling for missing or malformed files

Usage:
    python parse_logs.py
"""

import json

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_FILE = "logs_dataset_source.json"

# Visual separator width used in the formatted timeline output
SEPARATOR_WIDTH = 55


# ---------------------------------------------------------------------------
# Main parsing logic
# ---------------------------------------------------------------------------

def parse_and_display_logs(filepath: str) -> None:
    """
    Load a CloudTrail JSON log file and print each event as a formatted
    timeline entry.

    Args:
        filepath: Path to the JSON log file to be parsed.

    Raises:
        FileNotFoundError : Caught internally — printed as a user-friendly error.
        json.JSONDecodeError: Caught internally — printed as a user-friendly error.
    """
    try:
        # ── File I/O ────────────────────────────────────────────────────────
        # The `with` block guarantees the file handle is closed automatically
        # after reading, even if an exception is raised during `json.load()`.
        with open(filepath, "r", encoding="utf-8") as log_file:
            events = json.load(log_file)   # Deserialise JSON array → Python list

    except FileNotFoundError:
        # Raised when the OS cannot locate the file at `filepath`.
        print(f"[ERROR] Log file not found: '{filepath}'")
        print("        Ensure 'generate_mock_telemetry.py' has been run first.")
        return

    except json.JSONDecodeError as exc:
        # Raised when the file exists but its content is not valid JSON.
        print(f"[ERROR] Failed to parse JSON — {exc}")
        print("        The log file may be empty or corrupted.")
        return

    # ── Header ──────────────────────────────────────────────────────────────
    print("=" * SEPARATOR_WIDTH)
    print("   AWS CloudTrail — Event Timeline")
    print(f"   Source file : {filepath}")
    print(f"   Events found: {len(events)}")
    print("=" * SEPARATOR_WIDTH)

    # ── Iteration ───────────────────────────────────────────────────────────
    # Iterate through every event dictionary in the top-level list.
    # `enumerate` provides a 1-based counter for the human-readable index.
    for index, event in enumerate(events, start=1):

        # Extract the three required fields.
        # `userIdentity` is a nested dict, so we chain two key lookups.
        event_time  = event["eventTime"]
        event_name  = event["eventName"]
        user_name   = event["userIdentity"]["userName"]   # ← nested access

        # ── Formatted output ────────────────────────────────────────────────
        print(f"  [{index}] Time  : {event_time}")
        print(f"       Event : {event_name}")
        print(f"       User  : {user_name}")
        print("-" * SEPARATOR_WIDTH)

    print("   End of timeline.")
    print("=" * SEPARATOR_WIDTH)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parse_and_display_logs(SOURCE_FILE)