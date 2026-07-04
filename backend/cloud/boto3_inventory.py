"""Backward-compatible import for the shared AWS inventory provider."""

import sys
from shared import boto3_inventory as _implementation

sys.modules[__name__] = _implementation

