from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PRODUCT_ROOT = PROJECT_ROOT / "tests" / "integration" / "product"


def test_integration_product_tests_do_not_redefine_samples_dir_fixture() -> None:
    failures: list[str] = []
    for path in PRODUCT_ROOT.rglob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name == "samples_dir":
                failures.append(
                    f"{path.relative_to(PROJECT_ROOT)} redefines samples_dir instead of using tests/conftest.py"
                )
    assert failures == []
