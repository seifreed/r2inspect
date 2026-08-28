"""Map the legacy analysis result into the stable report/v1 envelope."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, cast
from uuid import uuid4

from pydantic_core import to_jsonable_python

from ..__version__ import __version__
from ..schemas.report_v1 import (
    AnalysisMetadataV1,
    FormatCommonV1,
    FormatReportV1,
    ReportV1,
    SampleInfoV1,
    ToolInfoV1,
)
from ..schemas.results_models import AnalysisResult
from .report_components import (
    analyzer_outcomes,
    capa_capabilities,
    findings,
    floss_artifacts,
)
from .report_typed import typed_analyzer_statuses
from .report_provenance import radare2_version as detected_radare2_version
from .report_provenance import tool_commit
from .report_security import normalized_security


def _json_safe(value: Any) -> Any:
    """Preserve binary evidence without asking JSON to decode it as UTF-8."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"encoding": "hex", "value": bytes(value).hex()}
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


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
    return "MACHO" if "MACH" in normalized else None


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
    raw_result = result.to_dict()
    typed_status = typed_analyzer_statuses(raw_result)
    raw = cast(dict[str, Any], to_jsonable_python(_json_safe(raw_result)))
    if typed_status:
        existing_status = raw.get("_analyzer_status")
        sidecar = dict(existing_status) if isinstance(existing_status, dict) else {}
        sidecar.update(typed_status)
        raw["_analyzer_status"] = sidecar
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
    endian: Literal["little", "big"] | None = (
        cast(Literal["little", "big"], raw_endian) if raw_endian in {"little", "big"} else None
    )
    format_family = _format_family(file_info.file_type)
    return ReportV1(
        tool=ToolInfoV1(
            version=__version__,
            backend=str(raw.get("backend", "r2")),
            commit=commit or tool_commit(),
            radare2_version=radare2_version or detected_radare2_version(),
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
        security=normalized_security(result),
        findings=findings(result),
        artifacts=floss_artifacts(raw),
        capabilities=capa_capabilities(raw),
        similarity=similarity,
        analyzers=analyzer_outcomes(raw),
        errors=[result.error] if result.error else [],
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
