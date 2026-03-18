"""Bridge integration tests for Phase 2 batch_processing coverage."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.product.test_cli_batch_processing_behaviors import *
