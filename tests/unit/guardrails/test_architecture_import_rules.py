"""Architecture guardrails for import boundaries and deprecated modules."""

from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = PROJECT_ROOT / "r2inspect"

DEPRECATED_MODULES = {
    "r2inspect.utils.logger",
    "r2inspect.utils.hashing",
    "r2inspect.utils.analyzer_factory",
    "r2inspect.utils.output",
    "r2inspect.utils.command_helpers",
    "r2inspect.utils.r2_helpers",
    "r2inspect.utils.error_handler",
    "r2inspect.utils.file_type",
    "r2inspect.utils.r2_suppress",
    "r2inspect.utils.ssdeep_loader",
    "r2inspect.utils.memory_manager",
    "r2inspect.utils.rate_limiter",
    "r2inspect.utils.retry_manager",
    "r2inspect.utils.circuit_breaker",
    "r2inspect.utils.output_csv",
    "r2inspect.utils.output_json",
    "r2inspect.utils.magic_detector",
    "r2inspect.utils.magic_patterns",
    "r2inspect.core.r2_session",
    "r2inspect.adapters.r2_commands",
    "r2inspect.application.analyzer_runner",
    "r2inspect.utils.analyzer_runner",
    "r2inspect.modules.function_domain",
    "r2inspect.modules.rich_header_domain",
}

DEPRECATED_SHIMS = {
    PACKAGE_ROOT / "utils" / "logger.py",
    PACKAGE_ROOT / "utils" / "hashing.py",
    PACKAGE_ROOT / "utils" / "analyzer_factory.py",
    PACKAGE_ROOT / "utils" / "output.py",
    PACKAGE_ROOT / "utils" / "command_helpers.py",
    PACKAGE_ROOT / "utils" / "r2_helpers.py",
    PACKAGE_ROOT / "utils" / "memory_manager.py",
    PACKAGE_ROOT / "utils" / "rate_limiter.py",
    PACKAGE_ROOT / "utils" / "retry_manager.py",
    PACKAGE_ROOT / "utils" / "circuit_breaker.py",
    PACKAGE_ROOT / "utils" / "output_csv.py",
    PACKAGE_ROOT / "utils" / "output_json.py",
    PACKAGE_ROOT / "utils" / "magic_detector.py",
    PACKAGE_ROOT / "utils" / "magic_patterns.py",
    PACKAGE_ROOT / "core" / "r2_session.py",
    PACKAGE_ROOT / "adapters" / "r2_commands.py",
    PACKAGE_ROOT / "application" / "analyzer_runner.py",
    PACKAGE_ROOT / "utils" / "analyzer_runner.py",
    PACKAGE_ROOT / "modules" / "function_domain.py",
    PACKAGE_ROOT / "modules" / "rich_header_domain.py",
}

APPLICATION_SHIMS = {
    PACKAGE_ROOT / "application" / "analyzer_runner.py",
}


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _module_name(path: Path) -> str:
    relative = path.relative_to(PROJECT_ROOT).with_suffix("")
    return ".".join(relative.parts)


def _resolved_imports(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    module_name = _module_name(path)
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


def _violations(paths: list[Path], predicate) -> list[str]:
    failures: list[str] = []
    for path in paths:
        for imported in _resolved_imports(path):
            if predicate(path, imported):
                failures.append(f"{path.relative_to(PROJECT_ROOT)} -> {imported}")
    return failures


def test_domain_does_not_depend_on_outer_layers() -> None:
    domain_paths = _python_files(PACKAGE_ROOT / "domain")
    forbidden_prefixes = (
        "r2inspect.application",
        "r2inspect.adapters",
        "r2inspect.cli",
        "r2inspect.infrastructure",
        "r2inspect.utils",
        "r2inspect.compat",
    )

    failures = _violations(
        domain_paths,
        lambda _path, imported: imported.startswith(forbidden_prefixes),
    )

    assert not failures, "Domain layer import violations:\n" + "\n".join(failures)


def test_application_does_not_depend_on_cli() -> None:
    application_paths = [
        path
        for path in _python_files(PACKAGE_ROOT / "application")
        if path not in APPLICATION_SHIMS
    ]

    failures = _violations(
        application_paths,
        lambda _path, imported: imported.startswith("r2inspect.cli"),
    )

    assert not failures, "Application layer import violations:\n" + "\n".join(failures)


def test_non_shim_modules_do_not_import_deprecated_paths() -> None:
    checked_paths = [
        path
        for path in _python_files(PACKAGE_ROOT)
        if path not in DEPRECATED_SHIMS and "compat" not in path.parts
    ]

    failures = _violations(
        checked_paths,
        lambda _path, imported: imported in DEPRECATED_MODULES,
    )

    assert not failures, "Deprecated import violations:\n" + "\n".join(failures)


def test_pipeline_does_not_import_adapters_directly() -> None:
    pipeline_paths = _python_files(PACKAGE_ROOT / "pipeline")

    failures = _violations(
        pipeline_paths,
        lambda _path, imported: imported.startswith("r2inspect.adapters"),
    )

    assert not failures, "Pipeline adapter import violations:\n" + "\n".join(failures)


def test_pipeline_does_not_import_utils() -> None:
    pipeline_paths = _python_files(PACKAGE_ROOT / "pipeline")

    failures = _violations(
        pipeline_paths,
        lambda _path, imported: imported.startswith("r2inspect.utils"),
    )

    assert not failures, "Pipeline utils import violations:\n" + "\n".join(failures)


def test_cli_does_not_import_domain_directly() -> None:
    cli_paths = _python_files(PACKAGE_ROOT / "cli")

    failures = _violations(
        cli_paths,
        lambda _path, imported: imported.startswith("r2inspect.domain"),
    )

    assert not failures, "CLI domain import violations:\n" + "\n".join(failures)


def test_runtime_layers_do_not_import_memory_or_rate_limiting_from_utils() -> None:
    checked_paths = [
        *_python_files(PACKAGE_ROOT / "core"),
        *_python_files(PACKAGE_ROOT / "cli"),
        PACKAGE_ROOT / "factory.py",
    ]
    forbidden = {
        "r2inspect.utils.memory_manager",
        "r2inspect.utils.rate_limiter",
    }

    failures = _violations(
        checked_paths,
        lambda _path, imported: imported in forbidden,
    )

    assert not failures, "Runtime utils import violations:\n" + "\n".join(failures)
