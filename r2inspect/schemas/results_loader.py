"""AnalysisResult loader facade."""

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
from .results_loader_support import (
    EXPORT_FIELDS,
    FUNCTION_FIELDS,
    IMPORT_FIELDS,
    INDICATOR_FIELDS,
    SECTION_FIELDS,
    YARA_FIELDS,
    load_collection as _load_collection_impl,
    load_file_info as _load_file_info_impl,
    load_hashing as _load_hashing_impl,
    load_security as _load_security_impl,
    load_simple as _load_simple_impl,
    set_if_present as _set_if_present_impl,
    load_timestamp as _load_timestamp_impl,
)


def from_dict(data: dict[str, Any]) -> AnalysisResult:
    result = AnalysisResult()
    for loader in (
        _load_file_info,
        _load_hashing,
        _load_security,
        _load_imports,
        _load_exports,
        _load_sections,
        _load_strings,
        _load_yara_matches,
        _load_functions,
        _load_anti_analysis,
        _load_packer,
        _load_crypto,
        _load_indicators,
        _load_error,
        _load_timestamp,
        _load_execution_time,
    ):
        loader(result, data)
    return result


def _load_file_info(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_file_info_impl(result, data, FileInfo)


def _load_hashing(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_hashing_impl(result, data, HashingResult)


def _load_security(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_security_impl(result, data, SecurityFeatures)


def _load_imports(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_collection_impl(result, data, "imports", ImportInfo, IMPORT_FIELDS)


def _load_exports(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_collection_impl(result, data, "exports", ExportInfo, EXPORT_FIELDS)


def _load_sections(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_collection_impl(result, data, "sections", SectionInfo, SECTION_FIELDS)


def _load_strings(result: AnalysisResult, data: dict[str, Any]) -> None:
    _set_if_present_impl(result, data, "strings")


def _load_yara_matches(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_collection_impl(result, data, "yara_matches", YaraMatch, YARA_FIELDS)


def _load_functions(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_collection_impl(result, data, "functions", FunctionInfo, FUNCTION_FIELDS)


def _load_anti_analysis(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_simple_impl(
        result,
        data,
        "anti_analysis",
        AntiAnalysisResult,
        {
            "anti_debug": ("anti_debug", False),
            "anti_vm": ("anti_vm", False),
            "anti_sandbox": ("anti_sandbox", False),
            "timing_checks": ("timing_checks", False),
            "techniques": ("techniques", []),
        },
    )


def _load_packer(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_simple_impl(
        result,
        data,
        "packer",
        PackerResult,
        {
            "is_packed": ("is_packed", False),
            "packer_type": ("packer_type", ""),
            "confidence": ("confidence", 0),
            "indicators": ("indicators", []),
        },
    )


def _load_crypto(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_simple_impl(
        result,
        data,
        "crypto",
        CryptoResult,
        {
            "algorithms": ("algorithms", []),
            "constants": ("constants", []),
            "functions": ("functions", []),
        },
    )


def _load_indicators(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_collection_impl(result, data, "indicators", Indicator, INDICATOR_FIELDS)


def _load_error(result: AnalysisResult, data: dict[str, Any]) -> None:
    _set_if_present_impl(result, data, "error")


def _load_timestamp(result: AnalysisResult, data: dict[str, Any]) -> None:
    _load_timestamp_impl(result, data)


def _load_execution_time(result: AnalysisResult, data: dict[str, Any]) -> None:
    result.execution_time = data.get("execution_time", 0.0)
