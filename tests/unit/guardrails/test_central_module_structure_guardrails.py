"""Guardrails for central facade modules that should stay small."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

FILE_LIMITS = {
    PROJECT_ROOT / "r2inspect" / "abstractions" / "base_analyzer.py": 180,
    PROJECT_ROOT / "r2inspect" / "abstractions" / "hashing_strategy.py": 280,
    PROJECT_ROOT / "r2inspect" / "interfaces" / "binary_analyzer.py": 120,
    PROJECT_ROOT / "r2inspect" / "registry" / "analyzer_registry.py": 220,
    PROJECT_ROOT / "r2inspect" / "infrastructure" / "r2_helpers.py": 220,
    PROJECT_ROOT / "r2inspect" / "infrastructure" / "magic_detector.py": 220,
    PROJECT_ROOT / "r2inspect" / "infrastructure" / "r2_session.py": 260,
    PROJECT_ROOT / "r2inspect" / "infrastructure" / "memory.py": 220,
    PROJECT_ROOT / "r2inspect" / "infrastructure" / "retry_manager.py": 220,
    PROJECT_ROOT / "r2inspect" / "adapters" / "r2pipe_queries.py": 220,
    PROJECT_ROOT / "r2inspect" / "adapters" / "validation.py": 180,
    PROJECT_ROOT / "r2inspect" / "schemas" / "metadata.py": 120,
    PROJECT_ROOT / "r2inspect" / "schemas" / "converters.py": 120,
    PROJECT_ROOT / "r2inspect" / "schemas" / "results_models.py": 160,
    PROJECT_ROOT / "r2inspect" / "schemas" / "results_loader.py": 180,
    PROJECT_ROOT / "r2inspect" / "lazy_loader.py": 220,
    PROJECT_ROOT / "r2inspect" / "cli_main.py": 220,
    PROJECT_ROOT / "r2inspect" / "modules" / "compiler_signatures.py": 220,
    PROJECT_ROOT / "r2inspect" / "modules" / "compiler_detector.py": 300,
    PROJECT_ROOT / "r2inspect" / "core" / "inspector.py": 220,
    PROJECT_ROOT / "r2inspect" / "core" / "result_aggregator.py": 160,
    PROJECT_ROOT / "r2inspect" / "error_handling" / "classifier.py": 360,
    PROJECT_ROOT / "r2inspect" / "security" / "validators.py": 280,
    PROJECT_ROOT / "r2inspect" / "registry" / "default_registry.py": 100,
    PROJECT_ROOT / "r2inspect" / "cli" / "batch_output.py": 340,
    PROJECT_ROOT / "r2inspect" / "cli" / "batch_processing.py": 320,
    PROJECT_ROOT / "r2inspect" / "cli" / "output_csv.py": 180,
    PROJECT_ROOT / "r2inspect" / "cli" / "output_formatters.py": 140,
    PROJECT_ROOT / "r2inspect" / "cli" / "validators.py": 220,
    PROJECT_ROOT / "r2inspect" / "cli" / "analysis_runner.py": 180,
    PROJECT_ROOT / "r2inspect" / "cli" / "display_sections_similarity.py": 140,
    PROJECT_ROOT / "r2inspect" / "cli" / "display_sections_hashing.py": 100,
    PROJECT_ROOT / "r2inspect" / "cli" / "display_base.py": 220,
    PROJECT_ROOT / "r2inspect" / "cli" / "commands" / "analyze_command.py": 180,
    PROJECT_ROOT / "r2inspect" / "cli" / "commands" / "base.py": 220,
    PROJECT_ROOT / "r2inspect" / "cli" / "commands" / "batch_command.py": 160,
    PROJECT_ROOT / "r2inspect" / "cli" / "commands" / "config_command.py": 100,
    PROJECT_ROOT / "r2inspect" / "cli" / "commands" / "interactive_command.py": 180,
}


def test_central_facade_modules_stay_small() -> None:
    failures: list[str] = []

    for path, limit in FILE_LIMITS.items():
        line_count = path.read_text(encoding="utf-8").count("\n") + 1
        if line_count > limit:
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} has {line_count} lines (limit {limit})"
            )

    assert failures == []
