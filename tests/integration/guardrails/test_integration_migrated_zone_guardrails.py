from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
TEST_ROOT = PROJECT_ROOT / "tests" / "integration"
MIGRATED_MARKERS = (
    "analysis_pipeline_real",
    "phase2_real_no_mocks_hashing_deep_paths",
    "phase2_pipeline",
    "phase3_real_no_mocks_hashing_similarity_paths",
    "pipeline_stages_real",
)


def test_migrated_integration_pipeline_tests_do_not_stay_in_root() -> None:
    failures: list[str] = []
    for path in TEST_ROOT.iterdir():
        if not path.is_file() or not path.name.startswith("test_"):
            continue
        if any(marker in path.name for marker in MIGRATED_MARKERS):
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} should move to integration/product or integration/historical"
            )
    assert failures == []
