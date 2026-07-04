"""Public detector API backed by the shared scanner engine."""

from .scanner_engine import (
    check_brute_force,
    check_disabled_account_with_key,
    check_dormant_admin,
    check_geo_anomaly,
    check_mfa_disabled,
    check_multiple_keys,
    check_never_used_key,
    check_no_password_rotation,
    check_off_hours_login,
    check_root_account_used,
    check_stale_account,
    check_stale_key,
    check_wildcard_permission,
    detect_field_level_drift,
)

__all__ = [name for name in globals() if name.startswith("check_")]
__all__.append("detect_field_level_drift")

