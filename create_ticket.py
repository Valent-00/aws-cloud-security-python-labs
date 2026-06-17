"""
create_ticket.py
----------------
Creates a structured security incident ticket as a JSON file inside
a managed `active_tickets/` directory.

Demonstrates:
    - Native `os` library for safe directory creation
    - Native `json` library for serialisation
    - `with open()` context manager for safe file I/O
    - Dictionary definition as a structured data record

Usage:
    python create_ticket.py
"""

import json
import os


# ---------------------------------------------------------------------------
# 1. DIRECTORY SETUP
# Safely create the `active_tickets/` folder if it does not already exist.
# `exist_ok=True` suppresses the error that would normally be raised if the
# directory is already present — making this call fully idempotent.
# ---------------------------------------------------------------------------

os.makedirs("active_tickets", exist_ok=True)


# ---------------------------------------------------------------------------
# 2. TICKET DEFINITION
# A dictionary representing a structured security incident record.
# ---------------------------------------------------------------------------

incident_ticket = {
    "ticket_id":        "SEC-2026-001",
    "timestamp":        "2026-06-17T23:18:00Z",
    "severity":         "CRITICAL",
    "incident_summary": "Unauthorized AWS CloudTrail StopLogging API call detected from external IP.",
    "status":           "OPEN"
}


# ---------------------------------------------------------------------------
# 3. FILE CREATION
# Write the ticket dictionary to disk as a human-readable JSON file.
# `with open()` guarantees the file handle is closed after the block exits,
# even if `json.dump()` raises an unexpected exception mid-write.
# ---------------------------------------------------------------------------

TICKET_PATH = "active_ticket/ticket_001.json"

with open(TICKET_PATH, "w", encoding="utf-8") as ticket_file:
    json.dump(incident_ticket, ticket_file, indent=4)


# ---------------------------------------------------------------------------
# 4. CONFIRMATION
# ---------------------------------------------------------------------------

print(f"[SUCCESS] Incident ticket created: '{TICKET_PATH}'")