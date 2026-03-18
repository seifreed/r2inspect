from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
TEST_ROOT = PROJECT_ROOT / "tests" / "unit"
MIGRATED_HISTORICAL = (
    "analysis_pipeline_",
    "batch_processing_additional_",
    "batch_processing_branches_",
    "batch_processing_helpers_",
    "batch_processing_real_",
    "cli_batch_processing",
    "pipeline_stages_common",
    "pipeline_stages_core",
    "pipeline_stages_detection",
    "pipeline_stages_format",
    "pipeline_stages_hashing",
    "pipeline_stages_metadata",
    "pipeline_stages_security",
)


def test_migrated_historical_tests_live_under_historical() -> None:
    failures: list[str] = []
    historical_root = TEST_ROOT / "historical"
    for path in TEST_ROOT.rglob("test_*.py"):
        if (
            path.is_relative_to(historical_root)
            or path.is_relative_to(TEST_ROOT / "product")
            or path.is_relative_to(TEST_ROOT / "guardrails")
        ):
            continue
        if any(marker in path.name for marker in MIGRATED_HISTORICAL):
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} should live under tests/unit/historical/"
            )
    assert failures == []


def test_new_product_or_guardrail_tests_do_not_return_to_unit_root() -> None:
    failures: list[str] = []
    for path in TEST_ROOT.iterdir():
        if not path.is_file() or not path.name.startswith("test_"):
            continue
        if any(marker in path.name for marker in MIGRATED_HISTORICAL):
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} should be categorized into product/ or historical/"
            )
    assert failures == []
