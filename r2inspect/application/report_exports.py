"""Deterministic report/v1 exports for analyst tooling."""

from __future__ import annotations

import html
from typing import Any

from ..schemas.report_v1 import ReportV1
from .report_exports_structured import to_misp, to_sarif, to_stix


def _report(value: ReportV1 | dict[str, Any]) -> ReportV1:
    return value if isinstance(value, ReportV1) else ReportV1.model_validate(value)


def to_html(value: ReportV1 | dict[str, Any]) -> str:
    report = _report(value)
    title = html.escape(f"r2inspect report: {report.sample.path or report.analysis.id}")
    rows = (
        "".join(
            "<tr>"
            f"<td>{html.escape(finding.rule_id)}</td>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{finding.confidence:.2f}</td>"
            "</tr>"
            for finding in report.findings
        )
        or '<tr><td colspan="4">No findings</td></tr>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #bbb;padding:.5rem;text-align:left}}th{{background:#eee}}</style>
</head><body><h1>{title}</h1><p>Profile: <strong>{html.escape(report.analysis.profile)}</strong> · Format: <strong>{html.escape(report.sample.detected_format or "unknown")}</strong></p>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Finding</th><th>Confidence</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>
"""


def export_report(value: ReportV1 | dict[str, Any], format_name: str) -> str | dict[str, Any]:
    normalized = format_name.lower()
    if normalized == "html":
        return to_html(value)
    exporters = {"sarif": to_sarif, "misp": to_misp, "stix": to_stix}
    if normalized not in exporters:
        raise ValueError(f"unsupported export format: {format_name}")
    return exporters[normalized](value)


__all__ = ["export_report", "to_html", "to_misp", "to_sarif", "to_stix"]
