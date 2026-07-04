"""Backward-compatible import for shared notification logic."""

import sys
from shared import notifications as _implementation

sys.modules[__name__] = _implementation

