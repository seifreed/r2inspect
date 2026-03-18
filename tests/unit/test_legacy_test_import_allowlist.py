from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = ROOT / "tests"

LEGACY_IMPORT_SNIPPETS = (
    "r2inspect.core.r2_session",
    "r2inspect.application.analyzer_runner",
    "r2inspect.utils.analyzer_runner",
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
    "r2inspect.modules.function_domain",
    "r2inspect.modules.rich_header_domain",
)


def test_legacy_test_imports_are_absent() -> None:
    offenders: list[str] = []

    for path in TESTS_ROOT.rglob("test_*.py"):
        relative = path.relative_to(ROOT).as_posix()
        if relative in {
            "tests/unit/test_architecture_import_rules.py",
            "tests/unit/test_legacy_test_import_allowlist.py",
        }:
            continue

        content = path.read_text(encoding="utf-8")
        for snippet in LEGACY_IMPORT_SNIPPETS:
            if snippet in content:
                offenders.append(f"{relative}: {snippet}")

    assert offenders == []
