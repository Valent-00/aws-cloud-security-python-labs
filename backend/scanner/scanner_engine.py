"""Backward-compatible import for the shared scanner engine."""

import os
import sys

_SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("SCANNER_LOG_DIR", _SCANNER_DIR)
os.environ.setdefault("SCANNER_STATE_DIR", os.path.join(_SCANNER_DIR, "state"))
os.environ.setdefault("SCANNER_LOG_TO_FILE", "true")

from shared import scanner_engine as _implementation

sys.modules[__name__] = _implementation
