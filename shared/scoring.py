"""Public scoring API backed by the shared scanner engine."""

from .scanner_engine import (
    ADMIN_ROLE_MULTIPLIER,
    MAX_RISK_SCORE,
    PRIVILEGED_ROLES,
    RISK_BASE_SCORES,
    SEVERITY_SCORE_RANGES,
    SEVERITY_SLA,
    Severity,
    calculate_risk_score,
    score_to_severity,
)

__all__ = [
    "ADMIN_ROLE_MULTIPLIER", "MAX_RISK_SCORE", "PRIVILEGED_ROLES",
    "RISK_BASE_SCORES", "SEVERITY_SCORE_RANGES", "SEVERITY_SLA",
    "Severity", "calculate_risk_score", "score_to_severity",
]

