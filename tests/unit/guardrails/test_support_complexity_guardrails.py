from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

FUNCTION_COMPLEXITY_LIMITS = {
    PROJECT_ROOT
    / "r2inspect"
    / "error_handling"
    / "unified_handler.py": {
        "_retry_execution": {"branches": 6, "depth": 2},
        "_circuit_break_execution": {"branches": 3, "depth": 1},
        "handle_errors": {"branches": 2, "depth": 1},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "infrastructure"
    / "r2_command_dispatch.py": {
        "_handle_bytes": {"branches": 11, "depth": 1},
        "_handle_simple": {"branches": 10, "depth": 2},
        "safe_cmdj": {"branches": 6, "depth": 2},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "binbloom_mixin.py": {
        "compare_bloom_filters": {"branches": 10, "depth": 2},
        "deserialize_bloom": {"branches": 8, "depth": 1},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "ssdeep_analyzer.py": {
        "_calculate_with_binary": {"branches": 8, "depth": 3},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "elf_analyzer.py": {
        "_read_section": {"branches": 8, "depth": 1},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "macho_analyzer.py": {
        "_extract_build_version": {"branches": 6, "depth": 4},
        "_extract_dylib_info": {"branches": 6, "depth": 3},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "modules"
    / "function_analyzer_support.py": {
        "generate_machoc_summary": {"branches": 6, "depth": 2},
        "analyze_function_coverage": {"branches": 6, "depth": 2},
    },
    PROJECT_ROOT
    / "r2inspect"
    / "registry"
    / "registry_registration.py": {
        "_handle_lazy_registration": {"branches": 7, "depth": 1},
        "_resolve_registration_mode": {"branches": 5, "depth": 1},
    },
}


def _function_metrics(path: Path) -> dict[str, tuple[int, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    metrics: dict[str, tuple[int, int]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        branches = 0
        max_depth = 0

        def walk(current: ast.AST, depth: int = 0) -> None:
            nonlocal branches, max_depth
            if isinstance(
                current,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.BoolOp,
                    ast.IfExp,
                    ast.Match,
                    ast.comprehension,
                ),
            ):
                branches += 1
                max_depth = max(max_depth, depth)
                depth += 1
            for child in ast.iter_child_nodes(current):
                walk(child, depth)

        walk(node)
        metrics[node.name] = (branches, max_depth)

    return metrics


def test_support_function_complexity_stays_bounded() -> None:
    failures: list[str] = []
    for path, limits in FUNCTION_COMPLEXITY_LIMITS.items():
        metrics = _function_metrics(path)
        for name, expected in limits.items():
            branches, depth = metrics[name]
            if branches > expected["branches"]:
                failures.append(
                    f"{path.relative_to(PROJECT_ROOT)}::{name} has {branches} branches "
                    f"(limit {expected['branches']})"
                )
            if depth > expected["depth"]:
                failures.append(
                    f"{path.relative_to(PROJECT_ROOT)}::{name} has nesting depth {depth} "
                    f"(limit {expected['depth']})"
                )
    assert failures == []
