"""Integration bridge for the next 5 unprioritized modules under 90% coverage."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# r2inspect/abstractions/hashing_strategy.py
from tests.unit.test_hashing_strategy_completion import *
from tests.unit.test_hashing_strategy_branch_paths import *
from tests.unit.test_hashing_strategy_block61 import *
from tests.unit.test_abstractions_hashing_strategy_block223 import *

# r2inspect/utils/ssdeep_loader.py
from tests.unit.test_utils_ssdeep_loader import *
from tests.unit.test_utils_ssdeep_loader_real import *
from tests.unit.test_utils_ssdeep_loader_block228 import *

# r2inspect/cli/display_statistics.py
from tests.unit.test_display_statistics_branch_paths import *

# r2inspect/error_handling/presets.py
from tests.unit.test_error_presets_block68 import *

# r2inspect/application/analysis_service.py
from tests.unit.test_application_small_branch_paths import *
