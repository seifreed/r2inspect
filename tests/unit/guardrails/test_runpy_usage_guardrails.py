from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
TEST_ROOT = PROJECT_ROOT / "tests"
ALLOWED_RUN_MODULE_TARGETS = {"r2inspect", "r2inspect.__main__"}


def test_runpy_usage_is_limited_to_entrypoints() -> None:
    failures: list[str] = []

    for path in sorted(TEST_ROOT.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "runpy" and node.func.attr == "run_module":
                    if (
                        not node.args
                        or not isinstance(node.args[0], ast.Constant)
                        or not isinstance(node.args[0].value, str)
                    ):
                        failures.append(
                            f"{path.relative_to(PROJECT_ROOT)} uses dynamic runpy.run_module target"
                        )
                        continue
                    target = node.args[0].value
                    if target not in ALLOWED_RUN_MODULE_TARGETS:
                        failures.append(
                            f"{path.relative_to(PROJECT_ROOT)} uses runpy.run_module on non-entrypoint target {target!r}"
                        )
                if node.func.value.id == "runpy" and node.func.attr == "run_path":
                    if not node.args:
                        failures.append(
                            f"{path.relative_to(PROJECT_ROOT)} uses dynamic runpy.run_path target"
                        )

    assert failures == []
