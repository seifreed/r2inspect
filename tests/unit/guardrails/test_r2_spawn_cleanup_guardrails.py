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


def _is_fixture_or_generator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    # @pytest.fixture with `yield ...; cleanup()` runs teardown even on failure,
    # so it is already leak-safe and must not be flagged.
    if any("fixture" in ast.unparse(dec) for dec in func.decorator_list):
        return True
    return any(isinstance(n, ast.Yield | ast.YieldFrom) for n in ast.walk(func))


def _opens_real_r2session(func: ast.AST) -> bool:
    # A real spawn constructs R2Session(...) without an injected ``opener=``
    # (fakes pass opener=, or set self.r2 = DummyR2()/override _open_with_timeout).
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "R2Session"
            and not any(kw.arg == "opener" for kw in node.keywords)
        ):
            return True
    return False


def _uses_fake_r2(func: ast.AST) -> bool:
    src = ast.unparse(func)
    return "DummyR2" in src or "FakeR2" in src or "_open_with_timeout" in src


def _calls_method(func: ast.AST, name: str) -> bool:
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == name
        for n in ast.walk(func)
    )


def test_real_r2session_tests_guarantee_cleanup() -> None:
    violations: list[str] = []
    for path in TESTS_ROOT.rglob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if _is_fixture_or_generator(node) or _uses_fake_r2(node):
                continue
            if (
                _opens_real_r2session(node)
                and _calls_method(node, "open")
                and (_calls_method(node, "close") or _calls_method(node, "quit"))
                and not _has_finally(node)
            ):
                violations.append(f"{path.relative_to(TESTS_ROOT)}::{node.name}")

    assert not violations, (
        "These tests open a real R2Session and close it outside try/finally; "
        "a failing assertion leaks the radare2 process:\n  " + "\n  ".join(sorted(violations))
    )
