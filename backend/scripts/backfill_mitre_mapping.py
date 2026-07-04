"""
scripts/backfill_mitre_mapping.py
==================================
One-time backfill: populate mitre_technique / mitre_tactic on FindingRecord
rows that were written before MITRE ATT&CK mapping existed.

Why this is needed
-------------------
New scans populate mitre_technique/mitre_tactic automatically — the
Finding dataclass computes them in __post_init__ before main.py ever
writes a row. But rows from scans run BEFORE this feature shipped have
NULL in those columns, and the scanner's fingerprint-based deduplication
means an unchanged mock dataset will report zero NEW findings on the next
scan — so those old rows would otherwise stay NULL forever. This script
fixes that without requiring a fresh scan.

Safe to re-run: it only touches rows where mitre_technique IS NULL.

Usage
-----
    cd backend
    python scripts/backfill_mitre_mapping.py
"""
import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BACKEND_DIR)
sys.path.insert(0, os.path.join(_BACKEND_DIR, "scanner"))

from models.database import FindingRecord, SessionLocal, init_db  # noqa: E402
from scanner_engine import get_mitre_mapping              # noqa: E402


def backfill() -> None:
    """Populate mitre_technique/mitre_tactic on any finding missing them."""
    init_db()  # ensures the mitre_technique/mitre_tactic columns exist first
    db = SessionLocal()
    try:
        rows = (
            db.query(FindingRecord)
              .filter(FindingRecord.mitre_technique.is_(None))
              .all()
        )
        mapped = 0
        for row in rows:
            mitre = get_mitre_mapping(row.alert_type)
            if mitre.technique:
                row.mitre_technique = mitre.technique
                row.mitre_tactic    = mitre.tactic
                mapped += 1
        db.commit()

        unmapped = len(rows) - mapped
        print(f"Checked {len(rows)} finding(s) with no prior MITRE mapping.")
        print(f"  → {mapped} mapped to an ATT&CK technique.")
        if unmapped:
            print(f"  → {unmapped} left as-is (behavioural signals with no "
                  f"standalone technique, e.g. Off-Hours Login / Geo Anomaly).")
    finally:
        db.close()


if __name__ == "__main__":
    backfill()