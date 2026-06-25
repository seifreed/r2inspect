from __future__ import annotations

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
from ..infrastructure.logging import get_logger
from ..abstractions.coercion_support import coerce_list

logger = get_logger(__name__)


def build_file_info(raw: dict[str, Any] | None) -> FileInfo:
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


def build_hashing_result(raw: dict[str, Any] | None) -> HashingResult:
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


def build_security_features(raw: dict[str, Any] | None) -> SecurityFeatures:
    if not raw or not isinstance(raw, dict):
        return SecurityFeatures()
    known = set(SecurityFeatures().to_dict())
    return SecurityFeatures(**{k: v for k, v in raw.items() if k in known})


def build_import_info(raw: dict[str, Any]) -> ImportInfo:
    return ImportInfo(
        name=raw.get("name", ""),
        library=raw.get("library", raw.get("lib", "")),
        address=str(raw.get("address", "")),
        ordinal=raw.get("ordinal", 0),
        category=raw.get("category", ""),
        risk_score=raw.get("risk_score", 0),
        risk_level=raw.get("risk_level", "Low"),
        risk_tags=coerce_list(raw.get("risk_tags", [])),
    )


def build_export_info(raw: dict[str, Any]) -> ExportInfo:
    return ExportInfo(
        name=raw.get("name", ""),
        address=str(raw.get("address", "")),
        ordinal=raw.get("ordinal", 0),
        size=raw.get("size", 0),
    )


def build_section_info(raw: dict[str, Any]) -> SectionInfo:
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
            suspicious_indicators=coerce_list(raw.get("suspicious_indicators", [])),
        )
    except Exception as exc:
        logger.debug("SectionInfo construction failed for '%s': %s", raw.get("name"), exc)
        return SectionInfo(name=raw.get("name", "unknown"))


def build_yara_match(raw: dict[str, Any]) -> YaraMatch:
    return YaraMatch(
        rule=raw.get("rule", ""),
        namespace=raw.get("namespace", ""),
        tags=coerce_list(raw.get("tags", [])),
        meta=raw.get("meta", {}),
        strings=coerce_list(raw.get("strings", [])),
    )


def build_function_info(raw: dict[str, Any]) -> FunctionInfo:
    return FunctionInfo(
        name=raw.get("name", ""),
        address=raw.get("address", raw.get("offset", 0)),
        size=raw.get("size", 0),
        complexity=raw.get("complexity", raw.get("cc", 0)),
        basic_blocks=raw.get("basic_blocks", raw.get("nbbs", 0)),
        call_refs=raw.get("call_refs", raw.get("callrefs", 0)),
        data_refs=raw.get("data_refs", raw.get("datarefs", 0)),
    )


def build_anti_analysis(raw: dict[str, Any] | None) -> AntiAnalysisResult:
    if not raw or not isinstance(raw, dict):
        return AntiAnalysisResult()
    return AntiAnalysisResult(
        anti_debug=raw.get("anti_debug", False),
        anti_vm=raw.get("anti_vm", False),
        anti_sandbox=raw.get("anti_sandbox", False),
        timing_checks=raw.get("timing_checks", False),
        techniques=coerce_list(raw.get("techniques", [])),
    )


def build_packer_result(raw: dict[str, Any] | None) -> PackerResult:
    if not raw or not isinstance(raw, dict):
        return PackerResult()
    return PackerResult(
        is_packed=raw.get("is_packed", False),
        packer_type=raw.get("packer_type", ""),
        confidence=raw.get("confidence", 0),
        indicators=coerce_list(raw.get("indicators", [])),
    )


def build_crypto_result(raw: dict[str, Any] | None) -> CryptoResult:
    if not raw or not isinstance(raw, dict):
        return CryptoResult()
    return CryptoResult(
        algorithms=coerce_list(raw.get("algorithms", [])),
        constants=coerce_list(raw.get("constants", [])),
        functions=coerce_list(raw.get("functions", [])),
    )


def build_indicator(raw: dict[str, Any]) -> Indicator:
    return Indicator(
        type=raw.get("type", ""),
        description=raw.get("description", ""),
        severity=raw.get("severity", "Low"),
    )
