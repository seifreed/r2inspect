from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
TEST_ROOT = PROJECT_ROOT / "tests"
HISTORICAL_TOKENS = ("block", "wave", "gaps", "coverage", "bridge", "remaining_edges")


def test_product_and_guardrail_test_names_avoid_historical_tokens() -> None:
    failures: list[str] = []
    allowed_roots = [
        TEST_ROOT / "unit" / "product",
        TEST_ROOT / "unit" / "guardrails",
        TEST_ROOT / "integration" / "product",
    ]
    for root in allowed_roots:
        for path in root.rglob("test_*.py"):
            if any(token in path.name for token in HISTORICAL_TOKENS):
                failures.append(f"{path.relative_to(PROJECT_ROOT)} uses historical naming token")
    assert failures == []
