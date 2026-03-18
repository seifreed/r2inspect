from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

FILE_LIMITS = {
    PROJECT_ROOT / "r2inspect" / "error_handling" / "unified_handler.py": 340,
    PROJECT_ROOT / "r2inspect" / "infrastructure" / "r2_command_dispatch.py": 290,
    PROJECT_ROOT / "r2inspect" / "modules" / "function_analyzer_support.py": 300,
    PROJECT_ROOT / "r2inspect" / "modules" / "binbloom_mixin.py": 340,
    PROJECT_ROOT / "r2inspect" / "modules" / "bindiff_domain.py": 320,
    PROJECT_ROOT / "r2inspect" / "modules" / "elf_analyzer.py": 290,
    PROJECT_ROOT / "r2inspect" / "modules" / "macho_analyzer.py": 300,
    PROJECT_ROOT / "r2inspect" / "modules" / "ssdeep_analyzer.py": 320,
    PROJECT_ROOT / "r2inspect" / "registry" / "registry_registration.py": 280,
}

FUNCTION_LIMITS = {
    PROJECT_ROOT
    / "r2inspect"
    / "error_handling"
    / "unified_handler.py": {
        "_retry_execution": 60,
        "_circuit_break_execution": 45,
        "handle_errors": 60,
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "binbloom_mixin.py": {
        "deserialize_bloom": 55,
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "ssdeep_analyzer.py": {
        "_calculate_with_binary": 65,
    },
    PROJECT_ROOT
    / "r2inspect"
    / "registry"
    / "registry_registration.py": {
        "register": 55,
        "_handle_lazy_registration": 55,
    },
}


def test_support_modules_stay_small() -> None:
    failures: list[str] = []
    for path, limit in FILE_LIMITS.items():
        line_count = path.read_text(encoding="utf-8").count("\n") + 1
        if line_count > limit:
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} has {line_count} lines (limit {limit})"
            )
    assert failures == []


def test_support_functions_stay_small() -> None:
    failures: list[str] = []
    for path, limits in FUNCTION_LIMITS.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name, limit in limits.items():
            node = nodes[name]
            size = node.end_lineno - node.lineno + 1
            if size > limit:
                failures.append(
                    f"{path.relative_to(PROJECT_ROOT)}::{name} has {size} lines (limit {limit})"
                )
    assert failures == []
