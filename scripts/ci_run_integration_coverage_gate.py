#!/usr/bin/env python3
"""Run integration tests with an explicit coverage gate and surface roadmap priorities.

This script executes integration tests, preserves pytest exit status, and emits a
stable report of the modules below the configured coverage threshold sorted by a
deterministic roadmap priority.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

PRIORITY_MAP: dict[str, str] = {
    "r2inspect/cli_main.py": "A",
    "r2inspect/cli/validators.py": "A",
    "r2inspect/compat/command_helpers.py": "A",
    "r2inspect/compat/error_handler.py": "A",
    "r2inspect/compat/r2_helpers.py": "A",
    "r2inspect/compat/r2_session.py": "A",
    "r2inspect/adapters/r2_commands.py": "A",
    "r2inspect/utils/circuit_breaker.py": "A",
    "r2inspect/cli/commands/analyze_command.py": "B",
    "r2inspect/cli/commands/config_command.py": "B",
    "r2inspect/cli/commands/batch_command.py": "B",
    "r2inspect/cli/commands/interactive_command.py": "B",
    "r2inspect/cli/batch_output.py": "B",
    "r2inspect/cli/display_sections_metadata.py": "B",
    "r2inspect/cli/display_sections_similarity.py": "B",
    "r2inspect/utils/memory_manager.py": "D",
    "r2inspect/utils/retry_manager.py": "D",
    "r2inspect/utils/rate_limiter.py": "D",
    "r2inspect/registry/metadata_extraction.py": "C",
    "r2inspect/registry/registry_queries.py": "C",
    "r2inspect/schemas/results_loader.py": "C",
    "r2inspect/schemas/converters.py": "C",
}

PHASE_LABELS = {
    "A": "Fase A — base/compat/r2",
    "B": "Fase B — cli/ux",
    "C": "Fase C — registry/schemas",
    "D": "Fase D — resiliencia",
}
PHASE_PRIORITY = ["A", "B", "C", "D"]
REPO_ROOT = Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run integration tests with explicit --cov-fail-under and report roadmap priorities."
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=70.0,
        help="Coverage threshold in percent.",
    )
    parser.add_argument(
        "--coverage-json",
        default=".coverage-gate/coverage-integration.json",
        help="Path to coverage JSON report produced by pytest.",
    )
    parser.add_argument(
        "--output",
        default=".coverage-gate/low_coverage_modules.json",
        help="Path to write a JSON summary of low covered modules.",
    )
    parser.add_argument(
        "--max-modules",
        type=int,
        default=200,
        help="Max number of low-covered modules to print.",
    )
    parser.add_argument(
        "--notes-path",
        default="coverage-notes.md",
        help="Path to append a concise gate run summary.",
    )
    parser.add_argument(
        "--append-notes",
        action="store_true",
        help="Append run summary to notes-path.",
    )
    return parser.parse_args()


def _run_pytest(threshold: float) -> tuple[int, list[str]]:
    artifacts_dir = REPO_ROOT / ".coverage-gate"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    coverage_xml = artifacts_dir / "coverage-integration.xml"
    coverage_json = artifacts_dir / "coverage-integration.json"
    junit_xml = artifacts_dir / "integration.junit.xml"
    command: list[str] = [
        sys.executable,
        "-m",
        "pytest",
        "tests/integration",
        "-q",
        "-m",
        "not slow",
        "--cov=r2inspect",
        "--cov-report=term-missing",
        f"--cov-report=xml:{coverage_xml}",
        f"--cov-report=json:{coverage_json}",
        f"--cov-fail-under={threshold}",
        f"--junitxml={junit_xml}",
    ]
    print(f"[ci] Running coverage gate: {' '.join(command[1:])}")
    result = subprocess.run(command, cwd=REPO_ROOT)
    return result.returncode, command


def _module_priority(path: str) -> tuple[int, str]:
    phase = PRIORITY_MAP.get(path)
    if phase is None:
        return len(PHASE_PRIORITY), "Z"
    return PHASE_PRIORITY.index(phase), phase


def _load_coverage(path: str) -> dict:
    data_path = Path(path)
    if not data_path.is_absolute():
        data_path = REPO_ROOT / data_path
    if not data_path.exists():
        raise FileNotFoundError(f"coverage json not found: {data_path}")
    return json.loads(data_path.read_text(encoding="utf-8"))


def _extract_below_threshold(data: dict, threshold: float, max_modules: int) -> list[dict]:
    files = data.get("files", {})
    low: list[dict] = []
    for path, info in files.items():
        if not path.startswith("r2inspect/"):
            continue
        summary = info.get("summary", {})
        coverage = summary.get("percent_covered", 100.0) or 0.0
        if coverage < threshold:
            phase_rank, phase_code = _module_priority(path)
            low.append(
                {
                    "path": path,
                    "coverage": float(coverage),
                    "phase": phase_code or "Z",
                    "priority": phase_rank,
                }
            )
    low.sort(key=lambda item: (item["priority"], item["coverage"], item["path"]))
    return low[:max_modules]


def _report(coverage_data: dict, threshold: float, max_modules: int, output: str | None) -> None:
    total = coverage_data.get("totals", {}).get("percent_covered")
    below = _extract_below_threshold(coverage_data, threshold, max_modules)
    print()
    print("=" * 80)
    if total is None:
        print("[ci] Coverage total: unavailable")
    else:
        print(f"[ci] Coverage total: {total:.2f}%")
    print(f"[ci] Threshold: {threshold}%")
    if not below:
        print("[ci] No tracked modules below threshold.")
        return
    print(f"[ci] Modules below {threshold}% (prioritized by roadmap):")
    for index, row in enumerate(below, start=1):
        phase_label = PHASE_LABELS.get(row["phase"], "Unprioritized")
        print(
            f"[ci] {index:>3}. {row['path']:<52} {row['coverage']:>6.2f}%  [phase={row['phase']}] ({phase_label})"
        )

    if output:
        out_path = Path(output)
        if not out_path.is_absolute():
            out_path = REPO_ROOT / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(
                {
                    "threshold": threshold,
                    "total_coverage": total,
                    "modules": below,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


def _append_notes(
    notes_path: str | None,
    command: list[str],
    status: int,
    threshold: float,
    coverage_data: dict,
    max_modules: int,
) -> None:
    if notes_path is None:
        return

    path = Path(notes_path)
    if not path.is_absolute():
        path = REPO_ROOT / path
    now = datetime.now(timezone.utc).astimezone()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    total = coverage_data.get("totals", {}).get("percent_covered")
    total_display = "N/A" if total is None else f"{total:.2f}%"
    modules = _extract_below_threshold(coverage_data, threshold, max_modules)

    entry = [
        "",
        f"### Gate run {timestamp}",
        "",
        "| Campo | Valor |",
        "| - | - |",
        f"| Comando | `{' '.join(command)}` |",
        f"| Umbral | {threshold}% |",
        f"| Estado | {'PASS' if status == 0 else 'FAIL'} ({status}) |",
        f"| Cobertura total | {total_display} |",
        f"| Módulos priorizados por umbral (`<= {threshold}%`) | {len(modules)} |",
    ]

    if modules:
        entry.append("")
        entry.append("| Ruta | Cobertura | Fase |")
        entry.append("| - | -: | - |")
        for row in modules[:12]:
            entry.append(f"| {row['path']} | {row['coverage']:>6.2f}% | {row['phase']} |")
    else:
        entry.append("")
        entry.append("- No hay módulos bajo el umbral.")

    entry_text = "\n".join(entry) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(entry_text)
    except Exception as exc:  # pragma: no cover - defensive logging path
        print(f"[ci] Warning: unable to append coverage notes to {path}: {exc}")


def main() -> int:
    args = _parse_args()
    status, command = _run_pytest(args.threshold)
    try:
        coverage_data = _load_coverage(args.coverage_json)
    except FileNotFoundError:
        print(f"[ci] Coverage json missing: {args.coverage_json}")
        return status
    _report(coverage_data, args.threshold, args.max_modules, args.output)
    if args.append_notes:
        _append_notes(
            args.notes_path, command, status, args.threshold, coverage_data, args.max_modules
        )
    return status


if __name__ == "__main__":
    raise SystemExit(main())
