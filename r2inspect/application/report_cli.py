"""Command-line entry points for report exports, comparison, and baselines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .report_compare import compare_reports
from .report_exports import export_report
from ..schemas.report_v1 import ReportV1


def _load(path: Path) -> ReportV1:
    return ReportV1.model_validate_json(path.read_text(encoding="utf-8"))


def _write(value: str | dict[str, Any], output: Path | None) -> None:
    payload = (
        value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True) + "\n"
    )
    if output:
        output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")


def export_main() -> None:
    parser = argparse.ArgumentParser(description="Export an r2inspect report/v1 artifact")
    parser.add_argument("report", type=Path)
    parser.add_argument("--format", choices=("html", "sarif", "misp", "stix"), required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    _write(export_report(_load(args.report), args.format), args.output)


def compare_main() -> None:
    parser = argparse.ArgumentParser(description="Compare two r2inspect report/v1 files")
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    _write(compare_reports(_load(args.left), _load(args.right)), args.output)


def baseline_main() -> None:
    parser = argparse.ArgumentParser(description="Check a report/v1 file against a baseline")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on-change", action="store_true")
    args = parser.parse_args()
    result = compare_reports(_load(args.baseline), _load(args.candidate))
    _write(result, args.output)
    if args.fail_on_change and result["status"] != "identical":
        raise SystemExit(1)


__all__ = ["baseline_main", "compare_main", "export_main"]
