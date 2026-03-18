"""Bridge integration tests for registry/schemas resilience (Phase C)."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.test_phase_c_registry_schemas_regression import *
from tests.unit.product.test_results_loader_behaviors import *
from tests.unit.test_schema_converters import *
from tests.unit.test_schemas_converters_block66 import *
from tests.unit.test_schemas_additional_coverage_real3 import *
from tests.unit.test_schemas_base_and_converters_block272 import *
