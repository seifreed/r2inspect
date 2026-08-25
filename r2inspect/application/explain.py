"""Human-readable explanations for report/v1 findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..schemas.report_v1 import FindingV1, ReportV1


def radare2_commands(finding: FindingV1) -> list[str]:
    commands: list[str] = []
    for location in finding.locations:
        address = (
            location.virtual_address if location.virtual_address is not None else location.offset
        )
        if address is not None:
            commands.extend((f"s 0x{address:x}", f"pdf @ 0x{address:x}"))
    return list(dict.fromkeys(commands))


def explain(report: ReportV1, finding_id: str) -> dict[str, Any]:
    finding = next(
        (
            item
            for item in report.findings
            if item.finding_id == finding_id or item.rule_id == finding_id
        ),
        None,
    )
    if finding is None:
        raise KeyError(f"finding not found: {finding_id}")
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "source_analyzer": finding.source_analyzer,
        "method": finding.method,
        "evidence": [item.model_dump(mode="json") for item in finding.evidence],
        "locations": [item.model_dump(mode="json") for item in finding.locations],
        "radare2_commands": radare2_commands(finding),
        "references": finding.references,
    }


def explain_file(report_path: Path, finding_id: str) -> dict[str, Any]:
    report = ReportV1.model_validate_json(report_path.read_text(encoding="utf-8"))
    return explain(report, finding_id)


def format_explanation(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


__all__ = ["explain", "explain_file", "format_explanation", "radare2_commands"]
