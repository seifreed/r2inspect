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
                features["file_type"] = file_info.get("core", {}).get("format", "")
                features["architecture"] = file_info.get("bin", {}).get("arch", "")
                features["bits"] = file_info.get("bin", {}).get("bits", 0)
                features["endian"] = file_info.get("bin", {}).get("endian", "")
                features["file_size"] = file_info.get("core", {}).get("size", 0)
            sections = self.adapter.get_sections() if self.adapter else []
            if sections:
                features["section_count"] = len(sections)
                features["section_names"] = sorted(
                    [s.get("name", "") for s in sections if s.get("name")]
                )
                features["section_sizes"] = [s.get("size", 0) for s in sections]
                features["executable_sections"] = len(
                    [s for s in sections if "x" in s.get("perm", "")]
                )
                features["writable_sections"] = len(
                    [s for s in sections if "w" in s.get("perm", "")]
                )
            imports = self.adapter.get_imports() if self.adapter else []
            if imports:
                features["import_count"] = len(imports)
                features["imported_dlls"] = list(
                    {
                        imp.get("libname") or imp.get("library", "")
                        for imp in imports
                        if imp.get("libname") or imp.get("library")
                    }
                )
                features["imported_functions"] = [
                    imp.get("name", "") for imp in imports if imp.get("name")
                ]
            exports = self.adapter.get_exports() if self.adapter else []
            if exports:
                features["export_count"] = len(exports)
                features["exported_functions"] = [
                    exp.get("name", "") for exp in exports if exp.get("name")
                ]
        except Exception as exc:
            logger.debug("Error extracting structural features: %s", exc)
        return features

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
                cfg_features = []
                for func in functions[:10]:
                    func_addr = func.get("offset", 0)
                    if func_addr:
                        cfg = self.adapter.get_cfg(func_addr) if self.adapter else {}
                        if cfg and isinstance(cfg, list) and cfg:
                            cfg_data = cfg[0]
                        elif isinstance(cfg, dict):
                            cfg_data = cfg
                        else:
                            cfg_data = {}
                        if cfg_data:
                            cfg_features.append(
                                {
                                    "nodes": len(cfg_data.get("blocks", [])),
                                    "edges": len(cfg_data.get("edges", [])),
                                    "complexity": calculate_cyclomatic_complexity(cfg_data),
                                }
                            )
                features["cfg_features"] = cfg_features
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
                api_strings = [s for s in string_values if is_api_string(s)]
                path_strings = [s for s in string_values if is_path_string(s)]
                url_strings = [s for s in string_values if is_url_string(s)]
                registry_strings = [s for s in string_values if is_registry_string(s)]
                features["api_strings"] = api_strings
                features["path_strings"] = path_strings
                features["url_strings"] = url_strings
                features["registry_strings"] = registry_strings
                features["categorized_strings"] = {}
                if api_strings:
                    features["categorized_strings"]["API"] = len(api_strings)
                if path_strings:
                    features["categorized_strings"]["Paths"] = len(path_strings)
                if url_strings:
                    features["categorized_strings"]["URLs"] = len(url_strings)
                if registry_strings:
                    features["categorized_strings"]["Registry"] = len(registry_strings)
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
                features["crypto_indicators"] = len(
                    [s for s in string_values if has_crypto_indicators(s)]
                )
                features["network_indicators"] = len(
                    [s for s in string_values if has_network_indicators(s)]
                )
                features["persistence_indicators"] = len(
                    [s for s in string_values if has_persistence_indicators(s)]
                )
            if imports:
                import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
                features["suspicious_apis"] = len(
                    [api for api in import_names if is_suspicious_api(api)]
                )
                features["crypto_apis"] = len([api for api in import_names if is_crypto_api(api)])
                features["network_apis"] = len([api for api in import_names if is_network_api(api)])
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
