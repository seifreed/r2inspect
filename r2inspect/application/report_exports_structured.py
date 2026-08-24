"""Structured report exports for SARIF, MISP, and STIX consumers."""

from __future__ import annotations

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
        f.rule_id: {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "properties": {"category": f.category},
        }
        for f in report.findings
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
            if location.virtual_address is not None:
                physical["region"] = {"byteOffset": location.virtual_address}
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
    attributes = [
        {
            "type": name,
            "category": "Payload delivery",
            "to_ids": True,
            "value": value,
            "comment": "r2inspect report/v1 sample hash",
        }
        for name, value in sorted(report.sample.hashes.items())
    ]
    attributes.extend(
        {
            "type": "text",
            "category": "Other",
            "to_ids": False,
            "value": f.rule_id,
            "comment": f.title,
        }
        for f in report.findings
    )
    return {
        "Event": {
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"r2inspect:{seed}")),
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
    valid_from = report.analysis.started_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": valid_from,
            "modified": valid_from,
            "name": report.tool.name,
            "identity_class": "organization",
        }
    ]
    for name, value in sorted(report.sample.hashes.items()):
        stix_name = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}.get(name)
        if stix_name:
            ident = uuid.uuid5(uuid.NAMESPACE_URL, f"r2inspect:{seed}:{name}")
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{ident}",
                    "created": valid_from,
                    "modified": valid_from,
                    "name": f"r2inspect {name} indicator",
                    "pattern": f"[file:hashes.'{stix_name}' = '{value}']",
                    "pattern_type": "stix",
                    "valid_from": valid_from,
                    "created_by_ref": identity_id,
                }
            )
    for finding in report.findings:
        ident = uuid.uuid5(uuid.NAMESPACE_URL, f"r2inspect:{seed}:{finding.finding_id}")
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": f"note--{ident}",
                "created": valid_from,
                "modified": valid_from,
                "content": f"{finding.rule_id}: {finding.title}",
                "object_refs": [identity_id],
                "created_by_ref": identity_id,
            }
        )
    bundle_id = uuid.uuid5(uuid.NAMESPACE_URL, f"r2inspect:{seed}:bundle")
    return {"type": "bundle", "id": f"bundle--{bundle_id}", "objects": objects}
