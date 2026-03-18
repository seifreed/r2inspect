from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
TEST_ROOT = PROJECT_ROOT / "tests"
HISTORICAL_TOKENS = ("wave", "block", "gaps", "remaining_edges", "coverage", "bridge")
BASELINE_COUNTS = {
    "tests/unit": 349,
    "tests/integration": 33,
    "tests/perf": 0,
}


def _historical_count(root: Path) -> int:
    return sum(
        1
        for path in root.rglob("test_*.py")
        if any(token in path.name for token in HISTORICAL_TOKENS)
    )


def test_historical_test_inventory_does_not_grow() -> None:
    failures: list[str] = []
    for rel_path, baseline in BASELINE_COUNTS.items():
        count = _historical_count(PROJECT_ROOT / rel_path)
        if count > baseline:
            failures.append(f"{rel_path} has {count} historical tests (baseline {baseline})")
    assert failures == []


def test_historical_tests_stay_in_unit_or_integration() -> None:
    failures: list[str] = []
    for path in TEST_ROOT.rglob("test_*.py"):
        if not any(token in path.name for token in HISTORICAL_TOKENS):
            continue
        if path.is_relative_to(TEST_ROOT / "unit") or path.is_relative_to(
            TEST_ROOT / "integration"
        ):
            continue
        failures.append(
            f"{path.relative_to(PROJECT_ROOT)} is historical-patterned but not under unit/ or integration/"
        )
    assert failures == []
