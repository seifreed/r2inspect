"""Helper loaders for AnalysisResult deserialization."""

from datetime import datetime
from typing import Any

from .results_models import (
    AnalysisResult,
    AntiAnalysisResult,
    CryptoResult,
    ExportInfo,
    FileInfo,
    FunctionInfo,
    HashingResult,
    ImportInfo,
    Indicator,
    PackerResult,
    SectionInfo,
    SecurityFeatures,
    YaraMatch,
)


# Convenience function for creating AnalysisResult from raw dict
def from_dict(data: dict[str, Any]) -> AnalysisResult:
    """
    Create an AnalysisResult from a dictionary.

    This is useful for deserializing analysis results from JSON.

    Args:
        data: Dictionary containing analysis data

    Returns:
        AnalysisResult instance
    """
    result = AnalysisResult()
    _load_file_info(result, data)
    _load_hashing(result, data)
    _load_security(result, data)
    _load_imports(result, data)
    _load_exports(result, data)
    _load_sections(result, data)
    _load_strings(result, data)
    _load_yara_matches(result, data)
    _load_functions(result, data)
    _load_anti_analysis(result, data)
    _load_packer(result, data)
    _load_crypto(result, data)
    _load_indicators(result, data)
    _load_error(result, data)
    _load_timestamp(result, data)
    _load_execution_time(result, data)
    return result


def _load_file_info(result: AnalysisResult, data: dict[str, Any]) -> None:
    fi = data.get("file_info")
    if not fi:
        return
    result.file_info = FileInfo(
        name=fi.get("name", ""),
        path=fi.get("path", ""),
        size=fi.get("size", 0),
        md5=fi.get("md5", ""),
        sha1=fi.get("sha1", ""),
        sha256=fi.get("sha256", ""),
        file_type=fi.get("file_type", ""),
        architecture=fi.get("architecture", ""),
        bits=fi.get("bits", 0),
        endian=fi.get("endian", ""),
        mime_type=fi.get("mime_type", ""),
    )


def _load_hashing(result: AnalysisResult, data: dict[str, Any]) -> None:
    h = data.get("hashing")
    if not h:
        return
    result.hashing = HashingResult(
        ssdeep=h.get("ssdeep", ""),
        tlsh=h.get("tlsh", ""),
        imphash=h.get("imphash", ""),
        impfuzzy=h.get("impfuzzy", ""),
        ccbhash=h.get("ccbhash", ""),
        simhash=h.get("simhash", ""),
        telfhash=h.get("telfhash", ""),
        rich_hash=h.get("rich_hash", ""),
        machoc_hash=h.get("machoc_hash", ""),
    )


def _load_security(result: AnalysisResult, data: dict[str, Any]) -> None:
    s = data.get("security")
    if not s:
        return
    result.security = SecurityFeatures(
        nx=s.get("nx", False),
        pie=s.get("pie", False),
        canary=s.get("canary", False),
        relro=s.get("relro", ""),
        aslr=s.get("aslr", False),
        seh=s.get("seh", False),
        guard_cf=s.get("guard_cf", False),
        authenticode=s.get("authenticode", False),
        fortify=s.get("fortify", False),
        rpath=s.get("rpath", False),
        runpath=s.get("runpath", False),
        high_entropy_va=s.get("high_entropy_va", False),
    )


def _load_imports(result: AnalysisResult, data: dict[str, Any]) -> None:
    imports = data.get("imports")
    if not imports:
        return
    result.imports = [
        ImportInfo(
            name=imp.get("name", ""),
            library=imp.get("library", ""),
            address=imp.get("address", ""),
            ordinal=imp.get("ordinal", 0),
            category=imp.get("category", ""),
            risk_score=imp.get("risk_score", 0),
            risk_level=imp.get("risk_level", "Low"),
            risk_tags=imp.get("risk_tags", []),
        )
        for imp in imports
    ]


def _load_exports(result: AnalysisResult, data: dict[str, Any]) -> None:
    exports = data.get("exports")
    if not exports:
        return
    result.exports = [
        ExportInfo(
            name=exp.get("name", ""),
            address=exp.get("address", ""),
            ordinal=exp.get("ordinal", 0),
            size=exp.get("size", 0),
        )
        for exp in exports
    ]


def _load_sections(result: AnalysisResult, data: dict[str, Any]) -> None:
    sections = data.get("sections")
    if not sections:
        return
    result.sections = [
        SectionInfo(
            name=sec.get("name", ""),
            virtual_address=sec.get("virtual_address", 0),
            virtual_size=sec.get("virtual_size", 0),
            raw_size=sec.get("raw_size", 0),
            entropy=sec.get("entropy", 0.0),
            permissions=sec.get("permissions", ""),
            is_executable=sec.get("is_executable", False),
            is_writable=sec.get("is_writable", False),
            is_readable=sec.get("is_readable", False),
            suspicious_indicators=sec.get("suspicious_indicators", []),
        )
        for sec in sections
    ]


def _load_strings(result: AnalysisResult, data: dict[str, Any]) -> None:
    if "strings" in data:
        result.strings = data["strings"]


def _load_yara_matches(result: AnalysisResult, data: dict[str, Any]) -> None:
    matches = data.get("yara_matches")
    if not matches:
        return
    result.yara_matches = [
        YaraMatch(
            rule=match.get("rule", ""),
            namespace=match.get("namespace", ""),
            tags=match.get("tags", []),
            meta=match.get("meta", {}),
            strings=match.get("strings", []),
        )
        for match in matches
    ]


def _load_functions(result: AnalysisResult, data: dict[str, Any]) -> None:
    functions = data.get("functions")
    if not functions:
        return
    result.functions = [
        FunctionInfo(
            name=func.get("name", ""),
            address=func.get("address", 0),
            size=func.get("size", 0),
            complexity=func.get("complexity", 0),
            basic_blocks=func.get("basic_blocks", 0),
            call_refs=func.get("call_refs", 0),
            data_refs=func.get("data_refs", 0),
        )
        for func in functions
    ]


def _load_anti_analysis(result: AnalysisResult, data: dict[str, Any]) -> None:
    aa = data.get("anti_analysis")
    if not aa:
        return
    result.anti_analysis = AntiAnalysisResult(
        anti_debug=aa.get("anti_debug", False),
        anti_vm=aa.get("anti_vm", False),
        anti_sandbox=aa.get("anti_sandbox", False),
        timing_checks=aa.get("timing_checks", False),
        techniques=aa.get("techniques", []),
    )


def _load_packer(result: AnalysisResult, data: dict[str, Any]) -> None:
    p = data.get("packer")
    if not p:
        return
    result.packer = PackerResult(
        is_packed=p.get("is_packed", False),
        packer_type=p.get("packer_type", ""),
        confidence=p.get("confidence", 0),
        indicators=p.get("indicators", []),
    )


def _load_crypto(result: AnalysisResult, data: dict[str, Any]) -> None:
    c = data.get("crypto")
    if not c:
        return
    result.crypto = CryptoResult(
        algorithms=c.get("algorithms", []),
        constants=c.get("constants", []),
        functions=c.get("functions", []),
    )


def _load_indicators(result: AnalysisResult, data: dict[str, Any]) -> None:
    indicators = data.get("indicators")
    if not indicators:
        return
    result.indicators = [
        Indicator(
            type=ind.get("type", ""),
            description=ind.get("description", ""),
            severity=ind.get("severity", "Low"),
        )
        for ind in indicators
    ]


def _load_error(result: AnalysisResult, data: dict[str, Any]) -> None:
    result.error = data.get("error")


def _load_timestamp(result: AnalysisResult, data: dict[str, Any]) -> None:
    ts = data.get("timestamp")
    if ts is None:
        return
    if isinstance(ts, str):
        try:
            result.timestamp = datetime.fromisoformat(ts)
        except ValueError:
            return
    elif isinstance(ts, datetime):
        result.timestamp = ts


def _load_execution_time(result: AnalysisResult, data: dict[str, Any]) -> None:
    result.execution_time = data.get("execution_time", 0.0)
