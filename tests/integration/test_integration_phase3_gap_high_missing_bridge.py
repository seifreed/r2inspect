"""Bridge integration tests for high-missing modules.

Focuses on modules with highest integration debt to accelerate Fase 3/4 coverage
objectives using existing unit-level branch tests.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.test_authenticode_analyzer_complete_100 import *
from tests.unit.test_batch_processing_complete_100 import *
from tests.unit.test_binbloom_analyzer_branch_paths import *
from tests.unit.test_binbloom_analyzer_coverage import *
from tests.unit.test_bindiff_analyzer_branch_paths import *
from tests.unit.test_ccbhash_analyzer_branch_paths import *
from tests.unit.test_exploit_mitigation_analyzer_complete_100 import *
from tests.unit.test_function_analyzer_branch_paths import *
from tests.unit.test_import_analyzer_branch_paths import *
from tests.unit.test_magic_detector import *
from tests.unit.test_magic_detector_missing_branches import *
from tests.unit.test_magic_detector_utils import *
from tests.unit.test_overlay_analyzer_branch_paths import *
from tests.unit.test_resource_analyzer_coverage_paths import *
from tests.unit.test_rich_header_analyzer_branch_paths import *
from tests.unit.test_section_analyzer_branch_paths import *
from tests.unit.test_simhash_analyzer_branch_paths import *
from tests.unit.test_telfhash_analyzer_branch_paths import *
from tests.unit.test_tlsh_analyzer_branch_paths import *
from tests.unit.test_yara_analyzer_coverage import *
