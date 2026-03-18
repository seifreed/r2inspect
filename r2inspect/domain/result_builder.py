"""Build typed AnalysisResult from raw pipeline dict output."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..domain.entities import (
    AntiAnalysisResult,
    CryptoResult,
    ExportInfo,
    FileInfo,
    FunctionInfo,
    HashingResult,
    ImportInfo,
    Indicator,
    PackerResult,
    YaraMatch,
)
from ..domain.format_types import SectionInfo, SecurityFeatures
from ..schemas.results_models import AnalysisResult


def _build_file_info(raw: dict[str, Any] | None) -> FileInfo:
    """Convert a raw file_info dict to a typed FileInfo dataclass."""
    if not raw or not isinstance(raw, dict):
        return FileInfo()
    return FileInfo(
        name=raw.get("name", ""),
        path=raw.get("path", ""),
        size=raw.get("size", 0),
        md5=raw.get("md5", ""),
        sha1=raw.get("sha1", ""),
        sha256=raw.get("sha256", ""),
        file_type=str(raw.get("file_type", raw.get("type", ""))),
        architecture=str(raw.get("architecture", raw.get("arch", ""))),
        bits=raw.get("bits", 0),
        endian=raw.get("endian", ""),
        mime_type=raw.get("mime_type", ""),
    )


def _build_hashing_result(raw: dict[str, Any] | None) -> HashingResult:
    """Convert a raw hashing dict to a typed HashingResult dataclass."""
    if not raw or not isinstance(raw, dict):
        return HashingResult()
    return HashingResult(
        ssdeep=raw.get("ssdeep", ""),
        tlsh=raw.get("tlsh", ""),
        imphash=raw.get("imphash", ""),
        impfuzzy=raw.get("impfuzzy", ""),
        ccbhash=raw.get("ccbhash", ""),
        simhash=raw.get("simhash", ""),
        telfhash=raw.get("telfhash", ""),
        rich_hash=raw.get("rich_hash", ""),
        machoc_hash=raw.get("machoc_hash", ""),
    )


def _build_security_features(raw: dict[str, Any] | None) -> SecurityFeatures:
    """Convert a raw security dict to a typed SecurityFeatures model."""
    if not raw or not isinstance(raw, dict):
        return SecurityFeatures(
            aslr=False,
            dep=False,
            seh=False,
            guard_cf=False,
            authenticode=False,
            nx=False,
            stack_canary=False,
            canary=False,
            pie=False,
            relro=False,
            rpath=False,
            runpath=False,
            fortify=False,
            high_entropy_va=False,
        )
    # Filter to only the known fields to avoid pydantic validation errors
    known_fields = {
        "aslr",
        "dep",
        "seh",
        "guard_cf",
        "authenticode",
        "nx",
        "stack_canary",
        "canary",
        "pie",
        "relro",
        "rpath",
        "runpath",
        "fortify",
        "high_entropy_va",
    }
    filtered = {k: v for k, v in raw.items() if k in known_fields}
    return SecurityFeatures(**filtered)


def _build_import_info(raw: dict[str, Any]) -> ImportInfo:
    return ImportInfo(
        name=raw.get("name", ""),
        library=raw.get("library", raw.get("lib", "")),
        address=str(raw.get("address", "")),
        ordinal=raw.get("ordinal", 0),
        category=raw.get("category", ""),
        risk_score=raw.get("risk_score", 0),
        risk_level=raw.get("risk_level", "Low"),
        risk_tags=raw.get("risk_tags", []),
    )


def _build_export_info(raw: dict[str, Any]) -> ExportInfo:
    return ExportInfo(
        name=raw.get("name", ""),
        address=str(raw.get("address", "")),
        ordinal=raw.get("ordinal", 0),
        size=raw.get("size", 0),
    )


def _build_section_info(raw: dict[str, Any]) -> SectionInfo:
    flags_val = raw.get("flags")
    if flags_val is not None and not isinstance(flags_val, str):
        flags_val = str(flags_val)
    perm_val = raw.get("permissions", raw.get("perm"))
    if perm_val is not None and not isinstance(perm_val, str):
        perm_val = str(perm_val)
    try:
        return SectionInfo(
            name=raw.get("name", "unknown"),
            virtual_address=raw.get("virtual_address", raw.get("vaddr", 0)),
            virtual_size=raw.get("virtual_size", raw.get("vsize", 0)),
            raw_size=raw.get("raw_size", raw.get("size", 0)),
            entropy=raw.get("entropy"),
            permissions=perm_val,
            is_executable=raw.get("is_executable", False),
            is_writable=raw.get("is_writable", False),
            is_readable=raw.get("is_readable", False),
            flags=flags_val,
            suspicious_indicators=raw.get("suspicious_indicators", []),
        )
    except Exception:
        return SectionInfo(
            name=raw.get("name", "unknown"),
            virtual_address=0,
            virtual_size=0,
            raw_size=0,
            entropy=None,
            permissions=None,
            is_executable=False,
            is_writable=False,
            is_readable=False,
            flags=None,
            suspicious_indicators=[],
        )


def _build_yara_match(raw: dict[str, Any]) -> YaraMatch:
    return YaraMatch(
        rule=raw.get("rule", ""),
        namespace=raw.get("namespace", ""),
        tags=raw.get("tags", []),
        meta=raw.get("meta", {}),
        strings=raw.get("strings", []),
    )


def _build_function_info(raw: dict[str, Any]) -> FunctionInfo:
    return FunctionInfo(
        name=raw.get("name", ""),
        address=raw.get("address", raw.get("offset", 0)),
        size=raw.get("size", 0),
        complexity=raw.get("complexity", raw.get("cc", 0)),
        basic_blocks=raw.get("basic_blocks", raw.get("nbbs", 0)),
        call_refs=raw.get("call_refs", raw.get("callrefs", 0)),
        data_refs=raw.get("data_refs", raw.get("datarefs", 0)),
    )


def _build_anti_analysis(raw: dict[str, Any] | None) -> AntiAnalysisResult:
    if not raw or not isinstance(raw, dict):
        return AntiAnalysisResult()
    return AntiAnalysisResult(
        anti_debug=raw.get("anti_debug", False),
        anti_vm=raw.get("anti_vm", False),
        anti_sandbox=raw.get("anti_sandbox", False),
        timing_checks=raw.get("timing_checks", False),
        techniques=raw.get("techniques", []),
    )


def _build_packer_result(raw: dict[str, Any] | None) -> PackerResult:
    if not raw or not isinstance(raw, dict):
        return PackerResult()
    return PackerResult(
        is_packed=raw.get("is_packed", False),
        packer_type=raw.get("packer_type", ""),
        confidence=raw.get("confidence", 0),
        indicators=raw.get("indicators", []),
    )


def _build_crypto_result(raw: dict[str, Any] | None) -> CryptoResult:
    if not raw or not isinstance(raw, dict):
        return CryptoResult()
    return CryptoResult(
        algorithms=raw.get("algorithms", []),
        constants=raw.get("constants", []),
        functions=raw.get("functions", []),
    )


def _build_indicator(raw: dict[str, Any]) -> Indicator:
    return Indicator(
        type=raw.get("type", ""),
        description=raw.get("description", ""),
        severity=raw.get("severity", "Low"),
    )


def _build_list(raw_list: Any, builder: Any) -> list[Any]:
    """Safely build a typed list from raw data."""
    if not raw_list or not isinstance(raw_list, list):
        return []
    result = []
    for item in raw_list:
        if isinstance(item, dict):
            result.append(builder(item))
        else:
            # Already a typed object or a primitive -- keep as-is
            result.append(item)
    return result


def build_analysis_result(raw: dict[str, Any]) -> AnalysisResult:
    """Convert raw pipeline dict to typed AnalysisResult.

    Extracts known keys into typed fields. Unknown keys are preserved
    in the underlying dict via ``to_dict()`` round-trip, but the typed
    wrapper provides safe attribute access with defaults.
    """
    # Handle already-typed results (idempotent call)
    if isinstance(raw, AnalysisResult):
        return raw

    # Build functions list only when the raw value is a list of dicts
    raw_functions = raw.get("functions")
    functions_list: list[Any] = []
    if isinstance(raw_functions, list):
        functions_list = _build_list(raw_functions, _build_function_info)

    return AnalysisResult(
        file_info=_build_file_info(raw.get("file_info")),
        hashing=_build_hashing_result(raw.get("hashing")),
        security=_build_security_features(raw.get("security")),
        imports=_build_list(raw.get("imports"), _build_import_info),
        exports=_build_list(raw.get("exports"), _build_export_info),
        sections=_build_list(raw.get("sections"), _build_section_info),
        strings=raw.get("strings", []),
        yara_matches=_build_list(raw.get("yara_matches", raw.get("yara")), _build_yara_match),
        functions=functions_list,
        anti_analysis=_build_anti_analysis(raw.get("anti_analysis")),
        packer=_build_packer_result(raw.get("packer")),
        crypto=_build_crypto_result(raw.get("crypto")),
        indicators=_build_list(raw.get("indicators"), _build_indicator),
        error=raw.get("error"),
        timestamp=(
            raw.get("timestamp", datetime.now(UTC))
            if not isinstance(raw.get("timestamp"), str)
            else datetime.fromisoformat(raw["timestamp"])
        ),
        execution_time=raw.get("execution_time", 0.0),
        _raw=raw,
    )
