"""Bridge integration tests for Phase A.

These tests are intentionally imported from unit test modules that already cover
CLI/compatibility smoke paths. Running them under integration makes this coverage
count toward the gated integration report without changing workflow split.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.test_phase_a_base_remedy import *
from tests.unit.test_phase1_cli_compat_smoke import *
