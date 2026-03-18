"""Guardrails for small function bodies in CLI facades."""

from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

FUNCTION_LIMITS = {
    PROJECT_ROOT
    / "r2inspect"
    / "cli"
    / "analysis_runner.py": {
        "run_analysis": 20,
        "setup_single_file_output": 10,
        "handle_main_error": 4,
    },
    PROJECT_ROOT
    / "r2inspect"
    / "cli"
    / "commands"
    / "base.py": {
        "configure_logging_levels": 4,
        "configure_quiet_logging": 4,
        "apply_thread_settings": 4,
        "_setup_analysis_options": 20,
        "_get_config": 15,
    },
}


def test_cli_facade_functions_stay_small() -> None:
    failures: list[str] = []

    for path, limits in FUNCTION_LIMITS.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nodes[node.name] = node
        for name, limit in limits.items():
            node = nodes[name]
            size = node.end_lineno - node.lineno + 1
            if size > limit:
                failures.append(
                    f"{path.relative_to(PROJECT_ROOT)}::{name} has {size} lines (limit {limit})"
                )

    assert failures == []
