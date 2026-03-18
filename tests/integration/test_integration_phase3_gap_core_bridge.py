"""Bridge integration tests for Phase 3 core-domain debt reduction.

This module imports targeted unit modules so their coverage is included in the
integration gate run without duplicating test logic.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.test_base_analyzer_completion import *
from tests.unit.test_core_file_validator_memory_block352 import *
from tests.unit.test_file_validator_branch_paths import *
from tests.unit.test_file_validator_validation import *
from tests.unit.test_hashing_branch_paths import *
from tests.unit.test_lazy_loader_block241 import *
from tests.unit.test_macho_analyzer_branch_paths import *
from tests.unit.test_packer_detector_branch_paths import *
from tests.unit.test_security_validators_block224 import *
from tests.unit.test_security_validators_block277 import *
from tests.unit.test_security_validators_block356 import *
from tests.unit.test_security_validators_branch_paths import *
from tests.unit.test_string_analyzer_branch_paths import *
from tests.unit.test_utils_hashing_block58 import *
