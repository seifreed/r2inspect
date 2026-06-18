"""Typed feature extraction for binary diffing.

``BinDiffFeatureExtractor`` owns the feature-extraction logic that used to
live in ``bindiff_analysis_support`` as untyped free functions.  It depends
on the segregated
:class:`~r2inspect.interfaces.binary_analyzer.BinaryAnalyzerInterface`
protocol and on the pure domain helpers in
:mod:`r2inspect.domain.formats.bindiff`, so it never reaches back into a
host analyzer's private members.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..adapters.file_system import default_file_system
from ..domain.formats.bindiff import (
    build_behavioral_signature,
    build_function_signature,
    build_string_signature,
    build_struct_signature,
    calculate_cyclomatic_complexity,
    calculate_rolling_hash,
    has_crypto_indicators,
    has_network_indicators,
    has_persistence_indicators,
    is_crypto_api,
    is_network_api,
    is_suspicious_api,
)
from ..infrastructure.command_helpers import cmd as cmd_helper
from ..infrastructure.logging import get_logger
from ..interfaces.binary_analyzer import BinaryAnalyzerInterface
from .string_classification import (
    is_api_string,
    is_path_string,
    is_registry_string,
    is_url_string,
)

logger = get_logger(__name__)


def _structural_file_info(file_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "file_type": file_info.get("core", {}).get("format", ""),
        "architecture": file_info.get("bin", {}).get("arch", ""),
        "bits": file_info.get("bin", {}).get("bits", 0),
        "endian": file_info.get("bin", {}).get("endian", ""),
        "file_size": file_info.get("core", {}).get("size", 0),
    }


def _structural_sections(sections: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "section_count": len(sections),
        "section_names": sorted([s.get("name", "") for s in sections if s.get("name")]),
        "section_sizes": [s.get("size", 0) for s in sections],
        "executable_sections": len([s for s in sections if "x" in s.get("perm", "")]),
        "writable_sections": len([s for s in sections if "w" in s.get("perm", "")]),
    }


def _structural_imports(imports: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "import_count": len(imports),
        "imported_dlls": list(
            {
                imp.get("libname") or imp.get("library", "")
                for imp in imports
                if imp.get("libname") or imp.get("library")
            }
        ),
        "imported_functions": [imp.get("name", "") for imp in imports if imp.get("name")],
    }


def _structural_exports(exports: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "export_count": len(exports),
        "exported_functions": [exp.get("name", "") for exp in exports if exp.get("name")],
    }


def _cfg_feature(cfg: Any) -> dict[str, Any] | None:
    if cfg and isinstance(cfg, list) and cfg:
        cfg_data = cfg[0]
    elif isinstance(cfg, dict):
        cfg_data = cfg
    else:
        cfg_data = {}
    if not cfg_data:
        return None
    return {
        "nodes": len(cfg_data.get("blocks", [])),
        "edges": len(cfg_data.get("edges", [])),
        "complexity": calculate_cyclomatic_complexity(cfg_data),
    }


_STRING_CLASSIFIERS = (
    ("api_strings", "API", is_api_string),
    ("path_strings", "Paths", is_path_string),
    ("url_strings", "URLs", is_url_string),
    ("registry_strings", "Registry", is_registry_string),
)


def _string_categories(string_values: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    categorized: dict[str, int] = {}
    for field, label, predicate in _STRING_CLASSIFIERS:
        matched = [s for s in string_values if predicate(s)]
        result[field] = matched
        if matched:
            categorized[label] = len(matched)
    result["categorized_strings"] = categorized
    return result


def _behavioral_string_indicators(string_values: list[str]) -> dict[str, Any]:
    return {
        "crypto_indicators": len([s for s in string_values if has_crypto_indicators(s)]),
        "network_indicators": len([s for s in string_values if has_network_indicators(s)]),
        "persistence_indicators": len([s for s in string_values if has_persistence_indicators(s)]),
    }


def _behavioral_import_indicators(import_names: list[str]) -> dict[str, Any]:
    return {
        "suspicious_apis": len([api for api in import_names if is_suspicious_api(api)]),
        "crypto_apis": len([api for api in import_names if is_crypto_api(api)]),
        "network_apis": len([api for api in import_names if is_network_api(api)]),
    }


class BinDiffFeatureExtractor:
    """Extracts comparison features from a single binary via a typed adapter."""

    def __init__(self, adapter: BinaryAnalyzerInterface | None, filepath: str) -> None:
        self.adapter = adapter
        self.filepath = filepath
        self.filename = Path(filepath).name

    def extract_structural(self) -> dict[str, Any]:
        features: dict[str, Any] = {}
        try:
            file_info = self.adapter.get_file_info() if self.adapter else {}
            if file_info:
                features.update(_structural_file_info(file_info))
            sections = self.adapter.get_sections() if self.adapter else []
            if sections:
                features.update(_structural_sections(sections))
            imports = self.adapter.get_imports() if self.adapter else []
            if imports:
                features.update(_structural_imports(imports))
            exports = self.adapter.get_exports() if self.adapter else []
            if exports:
                features.update(_structural_exports(exports))
        except Exception as exc:
            logger.debug("Error extracting structural features: %s", exc)
        return features

    def _collect_cfg_features(self, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        cfg_features = []
        for func in functions[:10]:
            # r2's aflj emits the function address as "addr" (not "offset"), so
            # this was always 0 and the CFG features were never collected.
            func_addr = func.get("addr") or func.get("offset", 0)
            if func_addr:
                cfg = self.adapter.get_cfg(func_addr) if self.adapter else {}
                feature = _cfg_feature(cfg)
                if feature is not None:
                    cfg_features.append(feature)
        return cfg_features

    def extract_functions(self) -> dict[str, Any]:
        features: dict[str, Any] = {}
        try:
            if self.adapter and hasattr(self.adapter, "analyze_all"):
                self.adapter.analyze_all()
            else:
                self._run_analysis()
            functions = self.adapter.get_functions() if self.adapter else []
            if functions:
                features["function_count"] = len(functions)
                features["function_sizes"] = [f.get("size", 0) for f in functions]
                features["function_names"] = [f.get("name", "") for f in functions if f.get("name")]
                features["cfg_features"] = self._collect_cfg_features(functions)
        except Exception as exc:
            logger.debug("Error extracting function features: %s", exc)
        return features

    def extract_strings(self) -> dict[str, Any]:
        features: dict[str, Any] = {}
        try:
            strings = self.adapter.get_strings() if self.adapter else []
            if strings:
                string_values = [s.get("string", "") for s in strings if s.get("string")]
                features["total_strings"] = len(string_values)
                features["unique_strings"] = len(set(string_values))
                features["string_lengths"] = [len(s) for s in string_values]
                features.update(_string_categories(string_values))
                unique_sorted = sorted(set(string_values))
                features["string_signature"] = hashlib.md5(
                    "|".join(unique_sorted).encode(), usedforsecurity=False
                ).hexdigest()
        except Exception as exc:
            logger.debug("Error extracting string features: %s", exc)
        return features

    def extract_bytes(self) -> dict[str, Any]:
        features: dict[str, Any] = {}
        try:
            entropy_info = self._entropy_pattern()
            if entropy_info:
                features["entropy_pattern"] = entropy_info.strip()
            try:
                data = self._read_head()
                if data:
                    features["rolling_hash"] = calculate_rolling_hash(data)
            except Exception as exc:
                logger.debug("Failed to compute rolling hash: %s", exc)
        except Exception as exc:
            logger.debug("Error extracting byte features: %s", exc)
        return features

    def extract_behavioral(self) -> dict[str, Any]:
        features: dict[str, Any] = {}
        try:
            strings = self.adapter.get_strings() if self.adapter else []
            imports = self.adapter.get_imports() if self.adapter else []
            if strings:
                string_values = [s.get("string", "") for s in strings if s.get("string")]
                features.update(_behavioral_string_indicators(string_values))
            if imports:
                import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
                features.update(_behavioral_import_indicators(import_names))
        except Exception as exc:
            logger.debug("Error extracting behavioral features: %s", exc)
        return features

    def generate_signatures(self, results: dict[str, Any]) -> dict[str, str]:
        signatures = {}
        try:
            signatures["structural"] = hashlib.md5(
                build_struct_signature(results.get("structural_features", {})).encode(),
                usedforsecurity=False,
            ).hexdigest()
            signatures["function"] = hashlib.md5(
                build_function_signature(results.get("function_features", {})).encode(),
                usedforsecurity=False,
            ).hexdigest()
            signatures["string"] = hashlib.md5(
                build_string_signature(results.get("string_features", {})).encode(),
                usedforsecurity=False,
            ).hexdigest()
            signatures["behavioral"] = hashlib.md5(
                build_behavioral_signature(results.get("behavioral_features", {})).encode(),
                usedforsecurity=False,
            ).hexdigest()
        except Exception as exc:
            logger.debug("Error generating signatures: %s", exc)
        return signatures

    def _run_analysis(self) -> Any:
        return cmd_helper(self.adapter, self.adapter, "aaa")

    def _entropy_pattern(self) -> str:
        if self.adapter and hasattr(self.adapter, "get_entropy_pattern"):
            return str(self.adapter.get_entropy_pattern())
        return str(cmd_helper(self.adapter, self.adapter, "p=e 100"))

    def _read_head(self) -> bytes:
        return default_file_system.read_bytes(self.filepath, size=8192)
