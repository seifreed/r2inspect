"""Architecture guardrails for structural quality."""

from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = PROJECT_ROOT / "r2inspect"

LAYER_LIMITS = {
    "domain": {"max_file_lines": 360, "max_function_lines": 45},
    "application": {"max_file_lines": 180, "max_function_lines": 95},
    "pipeline": {"max_file_lines": 360, "max_function_lines": 75},
}

FILE_LINE_EXCEPTIONS: set[Path] = set()

FUNCTION_LINE_EXCEPTIONS = set()


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _resolved_imports(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    module_name = ".".join(path.relative_to(PROJECT_ROOT).with_suffix("").parts)
    current_parts = module_name.split(".")
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:
                    imports.append(node.module)
                continue

            parent_parts = current_parts[: -node.level]
            if node.module:
                imports.append(".".join(parent_parts + node.module.split(".")))
            else:
                imports.append(".".join(parent_parts))

    return imports


def _function_spans(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    spans: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_lineno = getattr(node, "end_lineno", None)
        if end_lineno is None:
            continue
        spans.append((node.name, end_lineno - node.lineno + 1))
    return spans


def test_structural_limits_for_core_layers() -> None:
    failures: list[str] = []

    for layer, limits in LAYER_LIMITS.items():
        for path in _python_files(PACKAGE_ROOT / layer):
            file_lines = path.read_text(encoding="utf-8").count("\n") + 1
            if path not in FILE_LINE_EXCEPTIONS and file_lines > limits["max_file_lines"]:
                failures.append(
                    f"{path.relative_to(PROJECT_ROOT)} has {file_lines} lines "
                    f"(limit {limits['max_file_lines']})"
                )

            for function_name, span in _function_spans(path):
                if path in FUNCTION_LINE_EXCEPTIONS:
                    continue
                if span > limits["max_function_lines"]:
                    failures.append(
                        f"{path.relative_to(PROJECT_ROOT)}::{function_name} has {span} lines "
                        f"(limit {limits['max_function_lines']})"
                    )

    assert not failures, "Structural architecture violations:\n" + "\n".join(failures)
