"""Bridge integration tests for resource_analyzer coverage."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.unit.test_resource_analyzer_coverage_paths import *
