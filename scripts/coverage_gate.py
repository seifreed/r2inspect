#!/usr/bin/env python3
"""Utility to run coverage-related test suites with durable outputs.

The script captures:
- Raw pytest log per command.
- JUnit XML summary for reliable pass/fail counts.
- Optional coverage totals from pytest coverage report lines.
- A markdown update into coverage-notes.md with before/after deltas.

Usage:
    python scripts/coverage_gate.py
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CommandConfig:
    name: str
    label: str
    args: list[str]
    includes_coverage: bool


@dataclass
class CommandResult:
    name: str
    label: str
    command: str
    exit_code: int
    elapsed_seconds: float
    tests: int
    failures: int
    errors: int
    skipped: int
    total_coverage: int | None
    log_path: Path
    junit_path: Path | None
    command_returned: bool


def _run_pytest(
    repo_root: Path,
    command: CommandConfig,
    log_path: Path,
    junit_path: Path | None,
    extra_args: list[str],
) -> CommandResult:
    cmd = [sys.executable, "-m", "pytest"]
    cmd.extend(extra_args)
    cmd.extend(command.args)
    if junit_path is not None:
        cmd.append(f"--junitxml={junit_path}")

    command_text = " ".join(cmd)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8") as log_file:
        proc = subprocess.run(
            cmd,
            cwd=repo_root,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
    elapsed = time.perf_counter() - start
    log_text = log_path.read_text(errors="ignore")

    junit_metrics = None
    if junit_path is not None:
        junit_metrics = _parse_junit_summary(junit_path)
        if all(v == 0 for v in junit_metrics.values()):
            junit_metrics = _parse_progress_counts(log_text)
    else:
        junit_metrics = _parse_progress_counts(log_text)

    unit_totals = (
        junit_metrics if junit_metrics else {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    )

    coverage = None
    if command.includes_coverage:
        coverage = _parse_coverage_from_log(log_path)

    return CommandResult(
        name=command.name,
        label=command.label,
        command=command_text,
        exit_code=proc.returncode,
        elapsed_seconds=round(elapsed, 2),
        tests=unit_totals["tests"],
        failures=unit_totals["failures"],
        errors=unit_totals["errors"],
        skipped=unit_totals["skipped"],
        total_coverage=coverage,
        log_path=log_path,
        junit_path=junit_path if junit_path.exists() else None,
        command_returned=True,
    )


def _parse_junit_summary(xml_path: Path) -> dict[str, int]:
    if not xml_path.exists():
        return {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    root = ET.parse(xml_path).getroot()
    tests = failures = errors = skipped = 0
    # junit format can be testsuites->testsuite or directly testsuite.
    if root.tag == "testsuite":
        attrs = root.attrib
        tests += int(attrs.get("tests", "0"))
        failures += int(attrs.get("failures", "0"))
        errors += int(attrs.get("errors", "0"))
        skipped += int(attrs.get("skipped", "0"))
    else:
        for suite in root.findall(".//testsuite"):
            suite_at = suite.attrib
            tests += int(suite_at.get("tests", "0"))
            failures += int(suite_at.get("failures", "0"))
            errors += int(suite_at.get("errors", "0"))
            skipped += int(suite_at.get("skipped", "0"))
    return {
        "tests": tests,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
    }


def _parse_progress_counts(log_text: str) -> dict[str, int]:
    """Fallback metrics parser for `-q` output without junit output enabled."""
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for line in log_text.splitlines():
        stripped = line.strip()
        if not stripped.endswith("]"):
            continue
        match = re.search(r"\[\s*\d+%\s*\]$", stripped)
        if not match:
            continue
        symbols = stripped[: match.start()].strip()
        if not symbols:
            continue
        for char in symbols:
            if char in ".sSxfFX":
                counts["tests"] += 1
            if char in "sS":
                counts["skipped"] += 1
            elif char in "fF":
                counts["failures"] += 1
            elif char in "xXeE":
                counts["errors"] += 1
    return counts


def _parse_coverage_from_log(log_path: Path) -> int | None:
    text = log_path.read_text(errors="ignore")
    total_line = None
    for line in text.splitlines():
        if line.startswith("TOTAL") and "%" in line:
            total_line = line
    if total_line is None:
        return None
    match = re.search(r"\b(\d+)%$", total_line.strip())
    if match is None:
        return None
    return int(match.group(1))


def _markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _read_previous_coverage(notes_path: Path, command_label: str) -> int | None:
    if not notes_path.exists():
        return None
    text = notes_path.read_text(errors="ignore")
    # Prefer values written by this script itself; match latest table row with same command label.
    table_pattern = re.compile(
        rf"^\|\s*{re.escape(command_label)}\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|",
        re.MULTILINE,
    )
    table_matches = table_pattern.findall(text)
    if table_matches:
        before = table_matches[-1][1].strip()
        if before == "N/A":
            return None
        pct_match = re.search(r"(\d+)%", before)
        return int(pct_match.group(1)) if pct_match else None

    # Fallback for older free-form notes (legacy format in repo).
    legacy_pattern = re.compile(
        rf"^{re.escape(command_label)}[^\n]*?(\d+)%",
        re.MULTILINE,
    )
    legacy_matches = legacy_pattern.findall(text)
    if legacy_matches:
        return int(legacy_matches[-1])
    return None


def _update_notes(notes_path: Path, results: list[CommandResult]) -> None:
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []
    if notes_path.exists():
        existing = notes_path.read_text(errors="ignore")
    else:
        existing = "# coverage-notes\n\n"

    lines.append(existing.rstrip())
    lines.append("")
    lines.append(f"## Gate run {now}")
    lines.append("")
    lines.append(
        "| Comando | Antes | Después | Estado | Tests | Fallos | Errores | Skip | Cobertura | Logs | JUnit |"
    )
    lines.append("| - | -: | -: | - | -: | -: | -: | -: | - | - |")

    for result in results:
        before = _read_previous_coverage(notes_path, result.label)
        after = result.total_coverage
        if before is None:
            before_cell = "N/A"
        else:
            before_cell = f"{before}%"
        after_cell = f"{after}%" if after is not None else "N/A"
        state = "pass" if result.exit_code == 0 else f"fail ({result.exit_code})"
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_escape(result.label),
                    before_cell,
                    _markdown_escape(after_cell),
                    state,
                    str(result.tests),
                    str(result.failures),
                    str(result.errors),
                    str(result.skipped),
                    _markdown_escape(after_cell),
                    str(result.log_path),
                    str(result.junit_path) if result.junit_path else "N/A",
                ]
            )
            + " |"
        )
        lines.append("")
        lines.append(f"- `{result.name}` command")
        lines.append(f"  - Tiempo: {result.elapsed_seconds}s")
        lines.append(f"  - Command: `{result.command}`")
        lines.append("")

    notes_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run test suites and persist durable coverage summaries."
    )
    parser.add_argument(
        "--notes", default="coverage-notes.md", help="Coverage notes file to append results."
    )
    parser.add_argument(
        "--artifact-dir",
        default=".coverage-gate",
        help="Directory where junit/log artifacts are written.",
    )
    parser.add_argument(
        "--run-integration",
        action="store_true",
        default=True,
        help="Run integration suite (default: on).",
    )
    parser.add_argument(
        "--run-unit",
        action="store_true",
        default=True,
        help="Run unit suite (default: on).",
    )
    parser.add_argument(
        "--no-integration",
        dest="run_integration",
        action="store_false",
        help="Skip integration suite.",
    )
    parser.add_argument(
        "--no-unit",
        dest="run_unit",
        action="store_false",
        help="Skip unit suite.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    notes_path = repo_root / args.notes
    artifact_dir = repo_root / args.artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)

    suites: list[CommandConfig] = []
    if args.run_integration:
        suites.append(
            CommandConfig(
                name="integration",
                label='pytest -q tests/integration -m "not slow" --cov=r2inspect --cov-report=term-missing --cov-fail-under=70',
                args=[
                    "tests/integration",
                    "-q",
                    "-m",
                    "not slow",
                    "--cov=r2inspect",
                    "--cov-report=term-missing",
                    "--cov-fail-under=70",
                ],
                includes_coverage=True,
            )
        )
    if args.run_unit:
        suites.append(
            CommandConfig(
                name="unit",
                label='pytest -q tests/unit -m "not slow"',
                args=[
                    "tests/unit",
                    "-q",
                    "-m",
                    "not slow",
                ],
                includes_coverage=False,
            )
        )

    if not suites:
        print("No suites selected. Nothing to run.")
        return 0

    results: list[CommandResult] = []
    run_id = time.strftime("%Y%m%d_%H%M%S")
    for idx, suite in enumerate(suites, start=1):
        log_path = artifact_dir / f"{suite.name}_{run_id}_{idx}.log"
        junit_path = artifact_dir / f"{suite.name}_{run_id}_{idx}.junit.xml"
        result = _run_pytest(repo_root, suite, log_path, junit_path, extra_args=[])
        results.append(result)

    _update_notes(notes_path, results)
    failed = [r for r in results if r.exit_code != 0]
    for result in results:
        print(
            f"[{result.name}] exit={result.exit_code} tests={result.tests} "
            f"fail={result.failures} errors={result.errors} skipped={result.skipped} "
            f"coverage={result.total_coverage if result.total_coverage is not None else 'n/a'} "
            f"log={result.log_path}"
        )
    if failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
