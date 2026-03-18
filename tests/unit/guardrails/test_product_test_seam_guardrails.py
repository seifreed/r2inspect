from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PRODUCT_ROOTS = [
    PROJECT_ROOT / "tests" / "unit" / "product",
    PROJECT_ROOT / "tests" / "integration" / "product",
]


def test_product_tests_do_not_patch_r2inspect_module_globals_directly() -> None:
    failures: list[str] = []
    for root in PRODUCT_ROOTS:
        for path in root.rglob("test_*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "setattr"
                    and node.args
                ):
                    first = node.args[0]
                    if (
                        isinstance(first, ast.Constant)
                        and isinstance(first.value, str)
                        and first.value.startswith("r2inspect.")
                    ):
                        failures.append(
                            f"{path.relative_to(PROJECT_ROOT)} monkeypatches module global {first.value!r}"
                        )
                if isinstance(node.func, ast.Name) and node.func.id == "patch" and node.args:
                    first = node.args[0]
                    if (
                        isinstance(first, ast.Constant)
                        and isinstance(first.value, str)
                        and first.value.startswith("r2inspect.")
                    ):
                        failures.append(
                            f"{path.relative_to(PROJECT_ROOT)} patches module global {first.value!r}"
                        )
    assert failures == []
