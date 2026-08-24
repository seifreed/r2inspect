"""Deterministic report/v1 exports for analyst tooling."""

from __future__ import annotations

import html
import uuid
from datetime import UTC
from typing import Any

from ..schemas.report_v1 import ReportV1


def _report(value: ReportV1 | dict[str, Any]) -> ReportV1:
    return value if isinstance(value, ReportV1) else ReportV1.model_validate(value)


def _level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning"}.get(severity, "note")


def to_sarif(value: ReportV1 | dict[str, Any]) -> dict[str, Any]:
    report = _report(value)
    rules = {
        finding.rule_id: {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "properties": {"category": finding.category},
        }
        for finding in report.findings
    }
    results = []
    for finding in report.findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _level(finding.severity),
            "message": {"text": finding.title},
            "properties": {
                "confidence": finding.confidence,
                "source_analyzer": finding.source_analyzer,
            },
        }
        locations = []
        for location in finding.locations:
            physical: dict[str, Any] = {"artifactLocation": {"uri": report.sample.path or ""}}
            region: dict[str, Any] = {}
            if location.virtual_address is not None:
                region["byteOffset"] = location.virtual_address
            if region:
                physical["region"] = region
            locations.append({"physicalLocation": physical})
        if locations:
            result["locations"] = locations
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool.name,
                        "version": report.tool.version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def to_misp(value: ReportV1 | dict[str, Any]) -> dict[str, Any]:
    report = _report(value)
    seed = report.sample.hashes.get("sha256") or report.analysis.id
    event_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"r2inspect:{seed}"))
    attributes: list[dict[str, Any]] = []
    for hash_type, hash_value in sorted(report.sample.hashes.items()):
        attributes.append(
            {
                "type": hash_type,
                "category": "Payload delivery",
                "to_ids": True,
                "value": hash_value,
                "comment": "r2inspect report/v1 sample hash",
            }
        )
    for finding in report.findings:
        attributes.append(
            {
                "type": "text",
                "category": "Other",
                "to_ids": False,
                "value": finding.rule_id,
                "comment": finding.title,
            }
        )
    return {
        "Event": {
            "uuid": event_uuid,
            "info": f"r2inspect analysis {report.analysis.id}",
            "analysis": "0",
            "distribution": "0",
            "threat_level_id": (
                "1" if any(f.severity == "critical" for f in report.findings) else "3"
            ),
            "timestamp": report.analysis.started_at.isoformat(),
            "Tag": [{"name": f"r2inspect:profile={report.analysis.profile}"}],
            "Attribute": attributes,
        }
    }


def to_stix(value: ReportV1 | dict[str, Any]) -> dict[str, Any]:
    report = _report(value)
    seed = report.sample.hashes.get("sha256") or report.analysis.id
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'r2inspect:identity')}"
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": report.analysis.started_at.isoformat(),
            "modified": report.analysis.started_at.isoformat(),
            "name": report.tool.name,
            "identity_class": "organization",
        }
    ]
    valid_from = report.analysis.started_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    for hash_name, hash_value in sorted(report.sample.hashes.items()):
        stix_hash = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}.get(hash_name)
        if not stix_hash:
            continue
        indicator_id = (
            f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'r2inspect:{seed}:{hash_name}')}"
        )
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": valid_from,
                "modified": valid_from,
                "name": f"r2inspect {hash_name} indicator",
                "pattern": f"[file:hashes.'{stix_hash}' = '{hash_value}']",
                "pattern_type": "stix",
                "valid_from": valid_from,
                "created_by_ref": identity_id,
            }
        )
    for finding in report.findings:
        note_id = (
            f"note--{uuid.uuid5(uuid.NAMESPACE_URL, f'r2inspect:{seed}:{finding.finding_id}')}"
        )
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created": valid_from,
                "modified": valid_from,
                "content": f"{finding.rule_id}: {finding.title}",
                "object_refs": [identity_id],
                "created_by_ref": identity_id,
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, f'r2inspect:{seed}:bundle')}",
        "objects": objects,
    }


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
