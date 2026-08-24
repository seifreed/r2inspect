"""Stable comparison and baseline helpers for report/v1."""

from __future__ import annotations

from typing import Any

from ..schemas.report_v1 import ReportV1


def _report(value: ReportV1 | dict[str, Any]) -> ReportV1:
    return value if isinstance(value, ReportV1) else ReportV1.model_validate(value)


def _finding_key(finding: Any) -> tuple[str, str, str]:
    return finding.rule_id, finding.title, finding.severity


def compare_reports(
    left: ReportV1 | dict[str, Any], right: ReportV1 | dict[str, Any]
) -> dict[str, Any]:
    first = _report(left)
    second = _report(right)
    left_findings = {_finding_key(item) for item in first.findings}
    right_findings = {_finding_key(item) for item in second.findings}
    left_status = {item.analyzer_id: item.status.value for item in first.analyzers}
    right_status = {item.analyzer_id: item.status.value for item in second.analyzers}
    status_changes = {
        analyzer: {"before": left_status.get(analyzer), "after": right_status.get(analyzer)}
        for analyzer in sorted(set(left_status) | set(right_status))
        if left_status.get(analyzer) != right_status.get(analyzer)
    }
    changed = bool(left_findings ^ right_findings or status_changes)
    return {
        "schema_version": "r2inspect.compare/v1",
        "status": "changed" if changed else "identical",
        "samples": {
            "left": first.sample.hashes,
            "right": second.sample.hashes,
        },
        "findings": {
            "added": [
                {"rule_id": r, "title": t, "severity": s}
                for r, t, s in sorted(right_findings - left_findings)
            ],
            "removed": [
                {"rule_id": r, "title": t, "severity": s}
                for r, t, s in sorted(left_findings - right_findings)
            ],
        },
        "analyzer_status_changes": status_changes,
    }


__all__ = ["compare_reports"]
