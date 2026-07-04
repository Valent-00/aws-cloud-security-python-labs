"""
scripts/clear_alert_state.py
==============================
Resets the alert deduplication state so the next "Run Scan Now" treats
every finding as new — useful for demos, development, and FYP defense.

This is a DESTRUCTIVE operation — in a real production SOC you would
never clear alert state (it would trigger a full re-alert storm on every
known finding). Safe here because this is a single-account FYP demo.

Usage:
    cd backend
    python scripts/clear_alert_state.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.database import SessionLocal, AlertState, init_db

init_db()  # ensure tables exist
db = SessionLocal()

before = db.query(AlertState).count()
db.query(AlertState).delete()
db.commit()
db.close()

print(f"Cleared {before} AlertState rows.")
print("Next scan will treat all findings as new.")