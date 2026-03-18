"""Bridge integration tests for 95%+ stabilization.

This bridge targets single-line gaps and small-gap modules left after phase 5.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.test_residual_gaps import *
from tests.unit.test_small_gaps_wave3 import *
from tests.unit.test_small_module_gaps import *
from tests.unit.test_sections_file_display import *
from tests.unit.test_file_system_adapter import *
from tests.unit.test_final_small_gaps import *
from tests.unit.test_output_json_utils import *
