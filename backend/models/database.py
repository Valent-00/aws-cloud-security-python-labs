"""
models/database.py
==================
SQLAlchemy ORM models and database initialisation.

Tables
------
  ScanRun      — one row per scan execution (metadata + status)
  FindingRecord — one row per finding produced by a scan run
  AlertState   — persisted deduplication fingerprints (replaces alert_state.json)
  AnalystUser  — login accounts for SOC analysts (auth.py issues JWTs against this)

Design notes
------------
  * SQLite file lives at backend/data/iam_scanner.db (auto-created on startup).
  * All timestamps are stored as UTC ISO-8601 strings for portability.
  * Foreign key cascade ensures findings are deleted when a scan run is deleted.
  * String column lengths are explicit — good practice even with SQLite.

Security fix — DB-level role constraint (Fix M-2, 2026-07)
-----------------------------------------------------------
AnalystUser.role was a bare VARCHAR with only an application-level
convention ("analyst" | "admin") and a code comment enforcing it. The
database itself would accept role="superadmin", role="", or any typo,
so a bug in a provisioning script or a direct DB write could silently
create an account with a role the RBAC layer (auth.require_role) never
anticipated. This is a defense-in-depth gap: the app validated roles,
but the datastore did not.

The role column now carries a CHECK constraint pinning it to the
authoritative set in ALLOWED_ANALYST_ROLES. Two SQLite realities are
handled explicitly:
  * SQLite has no native ENUM type — the idiomatic equivalent is a
    CHECK (role IN (...)) constraint, which SQLite DOES enforce.
  * Base.metadata.create_all() only creates *missing tables*; it never
    adds a constraint to a table that already exists, and SQLite cannot
    ALTER TABLE ADD CONSTRAINT. So an existing iam_scanner.db needs the
    12-step table rebuild, implemented in _migrate_add_role_check_
    constraint() below — the same "stopgap until Alembic" philosophy the
    findings-column migration already uses.
"""

import logging
import os
import sqlite3
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from sqlalchemy.schema import CreateTable

logger = logging.getLogger("iam_scanner.database")

# ---------------------------------------------------------------------------
# Authoritative role set — single source of truth (Fix M-2)
# ---------------------------------------------------------------------------
# Referenced by the model's CHECK constraint AND the rebuild migration's
# data-validation step, so the two can never disagree about what a valid
# role is. If you add a role (e.g. "auditor"), add it here and the next
# startup's migration will rebuild the table to accept it.
ALLOWED_ANALYST_ROLES: tuple[str, ...] = ("analyst", "admin")
_ROLE_CHECK_NAME: str = "ck_analyst_users_role"


def _role_in_clause() -> str:
    """
    Build the SQL predicate ``role IN ('analyst', 'admin')`` from
    ALLOWED_ANALYST_ROLES. Single-quotes are escaped by doubling, per
    SQL string-literal rules, so an accidental apostrophe in a future
    role value can't break the DDL.
    """
    quoted = ", ".join("'" + r.replace("'", "''") + "'" for r in ALLOWED_ANALYST_ROLES)
    return f"role IN ({quoted})"


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
    acknowledged_by = Column(String(64), nullable=True)  # username of the analyst
    mitre_technique = Column(String(16), nullable=True)  # e.g. "T1098.001"
    mitre_tactic    = Column(String(64), nullable=True)  # e.g. "Persistence"

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


class AnalystUser(Base):
    """
    A SOC analyst login account.

    There is deliberately no self-registration endpoint — accounts are
    provisioned out-of-band via scripts/create_analyst.py. password is
    never stored in plaintext; only its bcrypt hash lives here (see
    auth.hash_password / auth.verify_password).

    Fix M-2: role is constrained at the database level to
    ALLOWED_ANALYST_ROLES via a CHECK constraint, so the datastore
    rejects any value the RBAC layer wouldn't understand — not just the
    application.
    """
    __tablename__ = "analyst_users"
    __table_args__ = (
        CheckConstraint(_role_in_clause(), name=_ROLE_CHECK_NAME),
    )

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(128), nullable=False)
    role            = Column(String(16), nullable=False, default="analyst")
    # role: "analyst" | "admin" — see auth.require_role() for RBAC gating,
    # and ALLOWED_ANALYST_ROLES above for the DB-enforced authoritative set.
    is_active       = Column(Boolean, nullable=False, default=True)
    created_at      = Column(String(32), nullable=False)   # UTC ISO-8601


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


def _migrate_add_missing_columns() -> None:
    """
    Add any columns to the `findings` table that the running code expects
    but an existing database (created before that column existed) doesn't
    have yet.

    `Base.metadata.create_all()` only creates *missing tables* — it never
    alters an existing table's columns. Without this, a database created
    before a column was added would hit "no such column: X" the first
    time a route tried to read it. Safe to run on every startup: it only
    ALTERs when a column is actually missing. This is a stopgap until the
    project adopts Alembic for real schema migrations.
    """
    with engine.connect() as conn:
        existing_cols = {
            row[1] for row in conn.exec_driver_sql("PRAGMA table_info(findings)")
        }
        for col, ddl_type in (
            ("mitre_technique",  "VARCHAR(16)"),
            ("mitre_tactic",     "VARCHAR(64)"),
            ("acknowledged_by",  "VARCHAR(64)"),
        ):
            if existing_cols and col not in existing_cols:
                conn.exec_driver_sql(f"ALTER TABLE findings ADD COLUMN {col} {ddl_type}")
        conn.commit()


def _migrate_add_role_check_constraint() -> None:
    """

    Safety properties
    -----------------
      * Idempotent: if the constraint is already present (fresh DBs get it
        from create_all, and re-runs see it), this returns immediately.
      * Non-destructive on bad data: if any existing row holds a role
        outside ALLOWED_ANALYST_ROLES, the rebuild would fail the new
        CHECK. Rather than crash startup or lose data, we log an error and
        skip — an operator must reconcile the offending rows first.
      * Index-preserving: explicit indexes on the old table are captured
        and replayed onto the rebuilt table, so query plans don't silently
        regress after the migration.
      * Transactional: the whole rebuild runs in one transaction with
        foreign_keys off (SQLite's documented rebuild procedure), so a
        failure mid-way rolls back to the original table intact.
    """
    # Generate the new table's DDL straight from the model (dialect-compiled
    # string only — no live connection needed), so its schema including the
    # CHECK constraint matches AnalystUser exactly. Only the first occurrence
    # (the table name in "CREATE TABLE analyst_users (") is renamed; the
    # constraint name, which also contains "analyst_users", is left untouched.
    create_new = str(CreateTable(AnalystUser.__table__).compile(engine)).strip()
    create_new = create_new.replace("analyst_users", "analyst_users__new", 1)
    cols = "id, username, hashed_password, role, is_active, created_at"

    # Drive the rebuild through the stdlib sqlite3 driver rather than a
    # SQLAlchemy Connection: SQLite's rebuild recipe requires toggling
    # `PRAGMA foreign_keys` OUTSIDE any transaction and issuing an explicit
    # BEGIN/COMMIT, which is cleaner to control at the DBAPI level. At startup
    # (single-threaded, before the app serves traffic) opening a second
    # connection to the same file is safe.
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()

        # Does the table even exist yet? (Fresh DB: create_all already made
        # it WITH the constraint, so the idempotency check below short-circuits.)
        row = cur.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='analyst_users'"
        ).fetchone()
        if not row or not row[0]:
            return
        table_sql = row[0]

        # Idempotency: constraint already present → nothing to do.
        if _ROLE_CHECK_NAME in table_sql or "role IN (" in table_sql:
            return

        # Guard: never rebuild if existing data would violate the new CHECK —
        # that would either fail the rebuild or (worse) risk data loss. Log
        # loudly and skip so an operator can reconcile the offending rows.
        placeholders = ", ".join(["?"] * len(ALLOWED_ANALYST_ROLES))
        bad = cur.execute(
            f"SELECT COUNT(*) FROM analyst_users WHERE role NOT IN ({placeholders})",
            tuple(ALLOWED_ANALYST_ROLES),
        ).fetchone()[0]
        if bad:
            logger.error(
                "Cannot add role CHECK constraint: %d analyst_users row(s) hold "
                "a role outside %s. Reconcile those rows, then restart. Skipping "
                "migration to avoid data loss.",
                bad, ALLOWED_ANALYST_ROLES,
            )
            return

        # Capture explicit indexes (sql IS NOT NULL — internal autoindexes
        # backing UNIQUE are recreated automatically by the new table schema).
        index_ddls = [
            r[0]
            for r in cur.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' "
                "AND tbl_name='analyst_users' AND sql IS NOT NULL"
            ).fetchall()
        ]

        # Autocommit mode so PRAGMA runs outside a transaction and BEGIN/COMMIT
        # are explicit — SQLite's documented safe-rebuild sequence.
        conn.isolation_level = None
        cur.execute("PRAGMA foreign_keys=OFF")
        cur.execute("BEGIN")
        try:
            cur.execute(create_new)
            cur.execute(
                f"INSERT INTO analyst_users__new ({cols}) "
                f"SELECT {cols} FROM analyst_users"
            )
            cur.execute("DROP TABLE analyst_users")
            cur.execute("ALTER TABLE analyst_users__new RENAME TO analyst_users")
            for ddl in index_ddls:
                cur.execute(ddl)
            cur.execute("COMMIT")
            logger.info(
                "Applied Fix M-2: added %s CHECK constraint to analyst_users "
                "(role IN %s).", _ROLE_CHECK_NAME, ALLOWED_ANALYST_ROLES,
            )
        except Exception:
            cur.execute("ROLLBACK")
            logger.exception(
                "Role CHECK constraint migration failed and was rolled back — "
                "analyst_users left unchanged."
            )
        finally:
            cur.execute("PRAGMA foreign_keys=ON")
    finally:
        conn.close()


def init_db() -> None:
    """
    Create all tables if they do not already exist, then apply any
    lightweight migrations needed by databases created before newer
    columns / constraints existed.
    """
    Base.metadata.create_all(bind=engine)
    _migrate_add_missing_columns()
    _migrate_add_role_check_constraint()


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()