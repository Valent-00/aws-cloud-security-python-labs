"""Legacy module name retained while callers migrate to the shared engine."""

import sys
from shared import scanner_engine as _implementation

sys.modules[__name__] = _implementation

