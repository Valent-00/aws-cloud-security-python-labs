"""
models/database.py
==================
SQLAlchemy ORM models and database initialisation.

Tables
------
  ScanRun      — one row per scan execution (metadata + status)
  FindingRecord — one row per finding produced by a scan run
  AlertState   — persisted deduplication fingerprints (replaces alert_state.json)

Design notes
------------
  * SQLite file lives at backend/data/iam_scanner.db (auto-created on startup).
  * All timestamps are stored as UTC ISO-8601 strings for portability.
  * Foreign key cascade ensures findings are deleted when a scan run is deleted.
  * String column lengths are explicit — good practice even with SQLite.
"""

import os
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

# ---------------------------------------------------------------------------
# Database file location
# ---------------------------------------------------------------------------
BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR: str = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH: str = os.path.join(DATA_DIR, "iam_scanner.db")
DATABASE_URL: str = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # required for SQLite + FastAPI
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanRun(Base):
    """
    One row per scan execution.

    Lifecycle: pending → running → completed | failed
    The frontend polls GET /api/v1/scans/{scan_id}/status until
    status is 'completed' or 'failed'.
    """
    __tablename__ = "scan_runs"

    id              = Column(Integer, primary_key=True, index=True)
    started_at      = Column(String(32), nullable=False)   # UTC ISO-8601
    completed_at    = Column(String(32), nullable=True)
    status          = Column(String(16), nullable=False, default="pending")
    # pending | running | completed | failed
    total_findings  = Column(Integer, default=0)
    critical_count  = Column(Integer, default=0)
    high_count      = Column(Integer, default=0)
    medium_count    = Column(Integer, default=0)
    low_count       = Column(Integer, default=0)
    info_count      = Column(Integer, default=0)
    error_message   = Column(Text, nullable=True)   # populated on failure
    ai_report       = Column(Text, nullable=True)   # Ollama output if available

    findings = relationship(
        "FindingRecord",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )


class FindingRecord(Base):
    """
    One row per security finding within a scan run.
    Mirrors the Finding dataclass from the scanner module.
    """
    __tablename__ = "findings"

    id           = Column(Integer, primary_key=True, index=True)
    scan_run_id  = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    username     = Column(String(128), nullable=False, index=True)
    alert_type   = Column(String(64),  nullable=False)
    severity     = Column(String(16),  nullable=False)   # Critical/High/Medium/Low/Info
    risk_score   = Column(Integer,     nullable=False)
    detail       = Column(Text,        nullable=False)
    sla          = Column(String(64),  nullable=False)
    fingerprint  = Column(String(64),  nullable=False, index=True)
    acknowledged = Column(Boolean,     default=False)
    ack_note     = Column(Text,        nullable=True)    # analyst note on ack
    ack_at       = Column(String(32),  nullable=True)    # UTC ISO-8601

    scan_run = relationship("ScanRun", back_populates="findings")


class AlertState(Base):
    """
    Persists deduplication fingerprints in the database instead of a JSON file.
    Each row is one active (unresolved) alert fingerprint.
    """
    __tablename__ = "alert_state"

    fingerprint  = Column(String(64), primary_key=True)
    first_seen   = Column(String(32), nullable=False)   # UTC ISO-8601
    resolved     = Column(Boolean,    default=False)
    resolved_at  = Column(String(32), nullable=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_db():
    """
    FastAPI dependency — yields a DB session and closes it after the request.

    Usage in a route:
        @app.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables if they do not already exist."""
    Base.metadata.create_all(bind=engine)


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()