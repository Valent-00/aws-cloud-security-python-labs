"""
analytics.py
=============
Aggregation queries over main.py's own scan history (ScanRun /
FindingRecord in SQLite) for the dashboard's charts: risk score
trends, MITRE ATT&CK coverage, recurring-issue breakdown, and
high-level scan statistics.

Scope note
----------
This operates on main.py's LOCAL scan history — the pipeline that
still runs against fetch_cloud_inventory()'s mock data, not the real
boto3-sourced findings the Lambda writes to S3 (see s3_reports.py for
those). Trend/coverage views here reflect "what this dashboard's own
scans have found," which is consistent with the rest of /api/v1/scans,
/api/v1/users, etc. — all of which already read from the same tables.

Every function here takes a SQLAlchemy Session and returns plain
dicts/lists (never raises a DB-shaped object back through the API
layer) — same separation FastAPI routes already rely on via Pydantic
response_models for everything else in this project.
"""
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.database import FindingRecord, ScanRun

_SEVERITY_RANK: dict[str, int] = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4,
}


def get_risk_trend(db: Session, limit: int = 30) -> list[dict]:
    """
    Per-scan risk score trend across the most recent completed scans,
    oldest-first — feeds a time-series chart of security posture.

    Severity counts and total_findings are read directly off ScanRun
    (already maintained there by _run_scan_worker on every scan) rather
    than recomputed from FindingRecord. Only avg/max risk score require
    a fresh aggregate, since ScanRun has no column for those — done as
    a single grouped query across all selected scans, not one query
    per scan, following the same N+1-avoidance this codebase already
    established in list_users().

    Args:
        db:    Active SQLAlchemy session.
        limit: Maximum number of recent completed scans to include.

    Returns:
        List of dicts, oldest scan first:
        {scan_id, started_at, avg_risk_score, max_risk_score,
         total_findings, critical_count, high_count, medium_count,
         low_count, info_count}

    Time  : O(limit)   Space: O(limit)
    """
    scans_desc = (
        db.query(ScanRun)
        .filter(ScanRun.status == "completed")
        .order_by(ScanRun.id.desc())
        .limit(limit)
        .all()
    )
    scans = list(reversed(scans_desc))  # oldest -> newest, correct for a trend line
    if not scans:
        return []

    scan_ids = [s.id for s in scans]
    risk_rows = (
        db.query(
            FindingRecord.scan_run_id.label("scan_run_id"),
            func.avg(FindingRecord.risk_score).label("avg_risk"),
            func.max(FindingRecord.risk_score).label("max_risk"),
        )
        .filter(FindingRecord.scan_run_id.in_(scan_ids))
        .group_by(FindingRecord.scan_run_id)
        .all()
    )
    risk_by_scan = {row.scan_run_id: (row.avg_risk, row.max_risk) for row in risk_rows}

    trend = []
    for scan in scans:
        avg_risk, max_risk = risk_by_scan.get(scan.id, (None, None))
        trend.append({
            "scan_id":        scan.id,
            "started_at":     scan.started_at,
            "avg_risk_score": round(avg_risk, 1) if avg_risk is not None else 0.0,
            "max_risk_score": int(max_risk) if max_risk is not None else 0,
            "total_findings": scan.total_findings,
            "critical_count": scan.critical_count,
            "high_count":     scan.high_count,
            "medium_count":   scan.medium_count,
            "low_count":      scan.low_count,
            "info_count":     scan.info_count,
        })
    return trend


def get_mitre_coverage(db: Session, scan_id: Optional[int] = None) -> list[dict]:
    """
    Finding counts grouped by MITRE ATT&CK tactic + technique, most
    frequent first — answers "where is our attack-surface coverage
    concentrated" for the dashboard's MITRE view.

    Findings with no MITRE mapping (mitre_technique IS NULL — e.g. a
    detector type with no MITRE_MAPPING entry, see
    api_mock_scanner.get_mitre_mapping()'s documented fallback) are
    excluded rather than shown as a misleading "Unknown: N" bucket.

    Args:
        db:      Active SQLAlchemy session.
        scan_id: Optional — scope to one scan instead of all findings
                 currently in the database.

    Returns:
        List of {mitre_tactic, mitre_technique, finding_count}, sorted
        by finding_count descending.

    Time  : O(f) where f = matching findings   Space: O(distinct technique pairs)
    """
    query = (
        db.query(
            FindingRecord.mitre_tactic,
            FindingRecord.mitre_technique,
            func.count(FindingRecord.id).label("finding_count"),
        )
        .filter(FindingRecord.mitre_technique.isnot(None))
    )
    if scan_id is not None:
        query = query.filter(FindingRecord.scan_run_id == scan_id)

    rows = (
        query.group_by(FindingRecord.mitre_tactic, FindingRecord.mitre_technique)
        .order_by(func.count(FindingRecord.id).desc())
        .all()
    )
    return [
        {
            "mitre_tactic":    row.mitre_tactic,
            "mitre_technique": row.mitre_technique,
            "finding_count":   row.finding_count,
        }
        for row in rows
    ]


def get_alert_type_breakdown(db: Session, scan_id: Optional[int] = None) -> list[dict]:
    """
    Finding counts grouped by alert_type, with each type's highest
    severity seen — answers "what's our biggest recurring problem,"
    sorted by frequency descending.

    A single GROUP BY (alert_type, severity) query, reduced to one
    entry per alert_type in Python — avoids the N+1 query-per-group
    pattern already fixed once in list_users() (e.g. NOT one extra
    query per alert_type to find its highest severity).

    Args:
        db:      Active SQLAlchemy session.
        scan_id: Optional — scope to one scan instead of all findings.

    Returns:
        List of {alert_type, finding_count, highest_severity}, sorted
        by finding_count descending.

    Time  : O(f) where f = matching findings   Space: O(distinct alert types)
    """
    query = db.query(
        FindingRecord.alert_type,
        FindingRecord.severity,
        func.count(FindingRecord.id).label("finding_count"),
    )
    if scan_id is not None:
        query = query.filter(FindingRecord.scan_run_id == scan_id)

    rows = query.group_by(FindingRecord.alert_type, FindingRecord.severity).all()

    by_alert_type: dict[str, dict] = {}
    for row in rows:
        entry = by_alert_type.setdefault(row.alert_type, {
            "alert_type": row.alert_type,
            "finding_count": 0,
            "highest_severity": "Info",
        })
        entry["finding_count"] += row.finding_count
        if _SEVERITY_RANK.get(row.severity, 99) < _SEVERITY_RANK.get(entry["highest_severity"], 99):
            entry["highest_severity"] = row.severity

    return sorted(by_alert_type.values(), key=lambda e: e["finding_count"], reverse=True)


def get_scan_statistics(db: Session) -> dict:
    """
    High-level counters across every scan run: how many have run, how
    many succeeded/failed, and average findings per completed scan.

    Args:
        db: Active SQLAlchemy session.

    Returns:
        {total_scans, completed_scans, failed_scans, in_progress_scans,
         success_rate_pct, avg_findings_per_scan}

    Time  : O(1) — all aggregate SQL, no row iteration   Space: O(1)
    """
    total = db.query(func.count(ScanRun.id)).scalar() or 0
    completed = (
        db.query(func.count(ScanRun.id)).filter(ScanRun.status == "completed").scalar() or 0
    )
    failed = (
        db.query(func.count(ScanRun.id)).filter(ScanRun.status == "failed").scalar() or 0
    )
    in_progress = total - completed - failed

    avg_findings = (
        db.query(func.avg(ScanRun.total_findings))
        .filter(ScanRun.status == "completed")
        .scalar()
    )

    return {
        "total_scans":            total,
        "completed_scans":        completed,
        "failed_scans":           failed,
        "in_progress_scans":      in_progress,
        "success_rate_pct":       round((completed / total) * 100, 1) if total else 0.0,
        "avg_findings_per_scan":  round(avg_findings, 1) if avg_findings is not None else 0.0,
    }