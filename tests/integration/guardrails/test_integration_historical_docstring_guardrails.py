from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
HISTORICAL_ROOT = PROJECT_ROOT / "tests" / "integration" / "historical"


def test_integration_historical_files_have_intent_docstrings() -> None:
    failures: list[str] = []
    required_terms = ("historical", "regression", "coverage", "transition", "edge", "bridge")
    for path in HISTORICAL_ROOT.rglob("test_*.py"):
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        docstring = (ast.get_docstring(module) or "").lower()
        if len(docstring.strip()) < 10:
            failures.append(f"{path.relative_to(PROJECT_ROOT)} needs a module docstring")
            continue
        if not any(term in docstring for term in required_terms):
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} needs a docstring explaining why it remains historical"
            )
    assert failures == []
