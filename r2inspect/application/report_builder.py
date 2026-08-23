"""Map the legacy analysis result into the stable report/v1 envelope."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Literal, cast
from uuid import uuid4

from pydantic_core import to_jsonable_python

from ..__version__ import __version__
from ..schemas.report_v1 import (
    AnalysisMetadataV1,
    AnalyzerOutcomeV1,
    AnalyzerStatus,
    EvidenceV1,
    FindingV1,
    FormatCommonV1,
    FormatReportV1,
    MitigationV1,
    ReportV1,
    SampleInfoV1,
    SecurityReportV1,
    ToolInfoV1,
)
from ..schemas.results_models import AnalysisResult


def _configuration_digest(configuration: dict[str, Any] | None) -> str | None:
    if configuration is None:
        return None
    encoded = json.dumps(
        configuration, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _format_details(raw: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = raw.get(key)
    return value if isinstance(value, dict) else None


def _format_family(file_type: str) -> str | None:
    normalized = file_type.upper()
    if normalized.startswith("PE"):
        return "PE"
    if normalized.startswith("ELF"):
        return "ELF"
    if "MACH" in normalized:
        return "MACHO"
    return None


def _normalized_security(result: AnalysisResult) -> SecurityReportV1:
    security = result.security
    file_type = result.file_info.file_type.upper()
    if file_type.startswith("ELF"):
        values = {
            "randomization": (security.pie, "elf.security_features.pie"),
            "no_execution": (security.nx, "elf.security_features.nx"),
            "stack_protection": (
                security.stack_canary or security.canary,
                "elf.security_features.stack_canary",
            ),
            "control_flow_integrity": (None, "elf.security_features"),
            "signature": (None, "elf.provenance"),
            "relocations": (bool(security.relro), "elf.security_features.relro"),
            "additional_hardening": (security.fortify, "elf.security_features.fortify"),
        }
    elif "MACH" in file_type:
        values = {
            "randomization": (security.pie, "macho.security_features.pie"),
            "no_execution": (security.nx, "macho.security_features.nx"),
            "stack_protection": (
                security.stack_canary or security.canary,
                "macho.security_features.stack_canary",
            ),
            "control_flow_integrity": (None, "macho.security_features"),
            "signature": (None, "macho.security_features.code_signature"),
            "relocations": (security.pie, "macho.security_features.pie"),
            "additional_hardening": (None, "macho.security_features"),
        }
    else:
        values = {
            "randomization": (security.aslr, "pe.security_features.aslr"),
            "no_execution": (security.dep, "pe.security_features.dep"),
            "stack_protection": (
                security.stack_canary or security.canary,
                "pe.security_features.stack_canary",
            ),
            "control_flow_integrity": (security.guard_cf, "pe.security_features.guard_cf"),
            "signature": (security.authenticode, "pe.security_features.authenticode"),
            "relocations": (security.aslr, "pe.security_features.aslr"),
            "additional_hardening": (security.seh, "pe.security_features.seh"),
        }
    return SecurityReportV1(
        normalized_mitigations={
            name: MitigationV1(enabled=enabled, source=source)
            for name, (enabled, source) in values.items()
        },
        format_specific=security.to_dict(),
    )


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", ".", value.lower()).strip(".") or "unknown"


def _findings(result: AnalysisResult) -> list[FindingV1]:
    findings: list[FindingV1] = []
    severity_aliases = {"info": "informational", "warning": "medium"}
    valid_severities = {"informational", "low", "medium", "high", "critical"}
    for indicator in result.indicators:
        severity = severity_aliases.get(indicator.severity.lower(), indicator.severity.lower())
        if severity not in valid_severities:
            severity = "informational"
        rule_id = f"legacy.indicator.{_slug(indicator.type)}"
        digest = hashlib.sha256(f"{rule_id}\0{indicator.description}".encode()).hexdigest()[:16]
        finding_severity = cast(
            Literal["informational", "low", "medium", "high", "critical"], severity
        )
        findings.append(
            FindingV1(
                finding_id=f"finding-{digest}",
                rule_id=rule_id,
                title=indicator.description or indicator.type or "Security indicator",
                category=indicator.type or "security",
                severity=finding_severity,
                confidence=0.5,
                source_analyzer="result_aggregator",
                method="legacy_indicator",
                evidence=[EvidenceV1(kind="description", value=indicator.description)],
            )
        )
    return findings


def _analyzer_outcomes(raw: dict[str, Any]) -> list[AnalyzerOutcomeV1]:
    outcomes: list[AnalyzerOutcomeV1] = []
    for analyzer_id, value in sorted(raw.items()):
        if not isinstance(value, dict) or not {"available", "error", "execution_time"}.intersection(
            value
        ):
            continue
        error = value.get("error")
        error_text = str(error).lower() if error else ""
        if error:
            if "timed out" in error_text or "timeout" in error_text:
                status = AnalyzerStatus.TIMED_OUT
            elif "unsupported" in error_text:
                status = AnalyzerStatus.UNSUPPORTED
            elif value.get("library_available") is False or "dependency" in error_text:
                status = AnalyzerStatus.DEPENDENCY_UNAVAILABLE
            else:
                status = AnalyzerStatus.FAILED
        elif value.get("available") is False:
            status = AnalyzerStatus.DEPENDENCY_UNAVAILABLE
        elif value.get("detected") is False:
            status = AnalyzerStatus.NOT_DETECTED
        else:
            status = AnalyzerStatus.COMPLETED
        duration = value.get("execution_time", 0.0)
        outcomes.append(
            AnalyzerOutcomeV1(
                analyzer_id=analyzer_id,
                status=status,
                duration=float(duration) if isinstance(duration, (int, float)) else 0.0,
                error=str(error) if error else None,
            )
        )
    return outcomes


def build_report_v1(
    result: AnalysisResult,
    *,
    profile: str = "standard",
    analysis_id: str | None = None,
    configuration: dict[str, Any] | None = None,
    commit: str | None = None,
    radare2_version: str | None = None,
) -> ReportV1:
    """Build a strict report/v1 envelope while preserving legacy details in extras."""
    raw = cast(dict[str, Any], to_jsonable_python(result.to_dict()))
    file_info = result.file_info
    hashes = {
        name: value
        for name, value in {
            "md5": file_info.md5,
            "sha1": file_info.sha1,
            "sha256": file_info.sha256,
        }.items()
        if value
    }
    similarity = [
        {"type": name, "value": value} for name, value in result.hashing.to_dict().items() if value
    ]
    bits: Literal[32, 64] | None = None
    if file_info.bits == 32:
        bits = 32
    elif file_info.bits == 64:
        bits = 64
    raw_endian = {"le": "little", "be": "big"}.get(file_info.endian, file_info.endian)
    endian: Literal["little", "big"] | None = None
    if raw_endian == "little":
        endian = "little"
    elif raw_endian == "big":
        endian = "big"
    errors = [result.error] if result.error else []
    format_family = _format_family(file_info.file_type)

    return ReportV1(
        tool=ToolInfoV1(
            version=__version__,
            commit=commit or os.getenv("R2INSPECT_COMMIT"),
            radare2_version=radare2_version or os.getenv("R2INSPECT_RADARE2_VERSION"),
        ),
        analysis=AnalysisMetadataV1(
            id=analysis_id or str(uuid4()),
            profile=profile,
            started_at=result.timestamp,
            duration=result.execution_time,
            configuration_digest=_configuration_digest(configuration),
        ),
        sample=SampleInfoV1(
            path=file_info.path or None,
            size=file_info.size,
            hashes=hashes,
            detected_format=format_family,
            architecture=file_info.architecture or None,
            bits=bits,
        ),
        format=FormatReportV1(
            common=FormatCommonV1(
                format=format_family,
                architecture=file_info.architecture or None,
                bits=bits,
                endian=endian,
            ),
            pe=_format_details(raw, "pe_info"),
            elf=_format_details(raw, "elf_info"),
            macho=_format_details(raw, "macho_info"),
        ),
        security=_normalized_security(result),
        findings=_findings(result),
        similarity=similarity,
        analyzers=_analyzer_outcomes(raw),
        errors=errors,
        warnings=(
            [str(item) for item in raw.get("warnings", [])]
            if isinstance(raw.get("warnings"), list)
            else []
        ),
        metrics=(
            raw.get("performance_statistics", {})
            if isinstance(raw.get("performance_statistics"), dict)
            else {}
        ),
        extras=raw,
    )


def report_payload_v1(result: AnalysisResult, options: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-compatible report payload for CLI and batch writers."""
    report = build_report_v1(
        result,
        profile=str(options.get("profile", "standard")),
        configuration=options,
    )
    return report.model_dump(mode="json")


__all__ = ["build_report_v1", "report_payload_v1"]
