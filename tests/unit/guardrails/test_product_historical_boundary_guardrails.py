from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PRODUCT_ROOTS = [
    PROJECT_ROOT / "tests" / "unit" / "product",
    PROJECT_ROOT / "tests" / "integration" / "product",
]


def test_product_tests_do_not_import_historical_test_modules() -> None:
    failures: list[str] = []
    for root in PRODUCT_ROOTS:
        for path in root.rglob("test_*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and ".historical" in node.module
                ):
                    failures.append(
                        f"{path.relative_to(PROJECT_ROOT)} imports historical module {node.module}"
                    )
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if ".historical" in alias.name:
                            failures.append(
                                f"{path.relative_to(PROJECT_ROOT)} imports historical module {alias.name}"
                            )
    assert failures == []
