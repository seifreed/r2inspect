"""Integration bridge for the next high-impact cluster under 90% coverage.

This suite imports branch-heavy unit tests to lift integration-reported
coverage on analyzers and inspector pipeline modules with high missing lines.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Inspector + helpers
from tests.unit.test_core_inspector_block247 import *
from tests.unit.test_core_inspector_phase2_core import *
from tests.unit.test_inspector_branch_paths import *
from tests.unit.test_inspector_helpers_coverage import *
from tests.unit.test_inspector_helpers_branch_paths import *
from tests.unit.test_inspector_helpers_and_aggregator_block332 import *

# Telfhash + ssdeep cluster
from tests.unit.test_telfhash_analyzer_complete_100 import *
from tests.unit.test_telfhash_analyzer_coverage import *
from tests.unit.test_telfhash_analyzer_branch_paths import *
from tests.unit.test_telfhash_analysis_paths import *
from tests.unit.test_telfhash_hashing import *
from tests.unit.test_telfhash_utils import *
from tests.unit.test_telfhash_remaining_gaps import *
from tests.unit.test_ssdeep_analyzer_complete_100 import *
from tests.unit.test_ssdeep_analyzer_coverage import *
from tests.unit.test_ssdeep_analyzer_branch_paths import *
from tests.unit.test_ssdeep_analyzer_phase2_paths import *

# Security and format analyzers
from tests.unit.test_anti_analysis_branch_paths import *
from tests.unit.test_anti_analysis_detection import *
from tests.unit.test_anti_analysis_domain import *
from tests.unit.test_macho_analyzer_complete_100 import *
from tests.unit.test_macho_analyzer_remaining import *
from tests.unit.test_macho_analyzer_extra_coverage import *
from tests.unit.test_macho_security_paths import *

# Pipeline stages under 90%
from tests.unit.test_pipeline_stages_detection_coverage import *
from tests.unit.test_pipeline_stages_detection_branch_paths import *
from tests.unit.test_pipeline_stages_security_branch_paths import *
