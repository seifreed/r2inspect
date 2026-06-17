"""Guardrail: tests that spawn a real r2 must guarantee cleanup.

A direct ``r2pipe.open(...)`` spawns a radare2 process. If ``quit()`` is only a
trailing statement, a failing assertion or a raising analyzer skips it and
orphans the process for the rest of the test session (the stale-pytest-radare2
class). Require any test function that calls ``r2pipe.open(...)`` to wrap its
work in ``try/finally`` so cleanup always runs.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[1]


def _is_r2pipe_open(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "r2pipe"
    )


def _has_finally(func: ast.AST) -> bool:
    return any(isinstance(n, ast.Try) and n.finalbody for n in ast.walk(func))


def _functions_opening_r2_without_finally(tree: ast.AST) -> list[str]:
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if any(_is_r2pipe_open(n) for n in ast.walk(node)) and not _has_finally(node):
            offenders.append(node.name)
    return offenders


def test_real_r2_spawning_tests_guarantee_cleanup() -> None:
    violations: list[str] = []
    for path in TESTS_ROOT.rglob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for func in _functions_opening_r2_without_finally(tree):
            violations.append(f"{path.relative_to(TESTS_ROOT)}::{func}")

    assert not violations, (
        "These tests call r2pipe.open() without a try/finally guaranteeing "
        "r2.quit(); they leak a radare2 process on the failure path:\n  "
        + "\n  ".join(sorted(violations))
    )
