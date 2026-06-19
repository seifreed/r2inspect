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
from collections.abc import Iterable
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


def _to_int(value: Any) -> int:
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return 0


def _string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _structural_file_info(file_info: dict[str, Any]) -> dict[str, Any]:
    core_info = file_info.get("core", {}) if isinstance(file_info, dict) else {}
    bin_info = file_info.get("bin", {}) if isinstance(file_info, dict) else {}
    if not isinstance(core_info, dict):
        core_info = {}
    if not isinstance(bin_info, dict):
        bin_info = {}
    return {
        "file_type": _string_value(core_info.get("format", "")),
        "architecture": _string_value(bin_info.get("arch", "")),
        "bits": _to_int(bin_info.get("bits", 0)),
        "endian": _string_value(bin_info.get("endian", "")),
        "file_size": _to_int(core_info.get("size", 0)),
    }


def _structural_sections(sections: list[dict[str, Any]]) -> dict[str, Any]:
    valid_sections = [section for section in sections if isinstance(section, dict)]
    return {
        "section_count": len(valid_sections),
        "section_names": sorted(
            [name for s in valid_sections if (name := _string_value(s.get("name")))]
        ),
        "section_sizes": [_to_int(s.get("size", 0)) for s in valid_sections],
        "executable_sections": len(
            [s for s in valid_sections if "x" in _string_value(s.get("perm"))]
        ),
        "writable_sections": len([s for s in valid_sections if "w" in _string_value(s.get("perm"))]),
    }


def _structural_imports(imports: list[dict[str, Any]]) -> dict[str, Any]:
    valid_imports = [imp for imp in imports if isinstance(imp, dict)]
    return {
        "import_count": len(valid_imports),
        "imported_dlls": sorted(
            {
                dll
                for imp in valid_imports
                if (dll := _string_value(imp.get("libname") or imp.get("library")))
            }
        ),
        "imported_functions": [
            name for imp in valid_imports if (name := _string_value(imp.get("name")))
        ],
    }


def _structural_exports(exports: list[dict[str, Any]]) -> dict[str, Any]:
    valid_exports = [exp for exp in exports if isinstance(exp, dict)]
    return {
        "export_count": len(valid_exports),
        "exported_functions": [
            name for exp in valid_exports if (name := _string_value(exp.get("name")))
        ],
    }


def _cfg_feature(cfg: Any) -> dict[str, Any] | None:
    if isinstance(cfg, dict):
        cfg_data = cfg
    elif isinstance(cfg, list):
        cfg_data = cfg[0] if cfg else {}
    elif isinstance(cfg, (str, bytes)) or not isinstance(cfg, Iterable):
        cfg_data = {}
    else:
        cfg_items = list(cfg)
        cfg_data = cfg_items[0] if cfg_items else {}
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
            if not isinstance(func, dict):
                continue
            # r2's aflj emits the function address as "addr" (not "offset"), so
            # this was always 0 and the CFG features were never collected.
            func_addr = _to_int(func.get("addr") or func.get("offset", 0))
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
            valid_functions = [func for func in functions if isinstance(func, dict)]
            if valid_functions:
                features["function_count"] = len(valid_functions)
                features["function_sizes"] = [_to_int(f.get("size", 0)) for f in valid_functions]
                features["function_names"] = [
                    name for f in valid_functions if isinstance(name := f.get("name"), str) and name
                ]
                features["cfg_features"] = self._collect_cfg_features(valid_functions)
        except Exception as exc:
            logger.debug("Error extracting function features: %s", exc)
        return features

    def extract_strings(self) -> dict[str, Any]:
        features: dict[str, Any] = {}
        try:
            strings = self.adapter.get_strings() if self.adapter else []
            if strings:
                string_values = [
                    string_value
                    for s in strings
                    if isinstance(s, dict)
                    and (string_value := _string_value(s.get("string")))
                ]
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
            if isinstance(entropy_info, str) and entropy_info:
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
                string_values = [
                    string_value
                    for s in strings
                    if isinstance(s, dict)
                    and (string_value := _string_value(s.get("string")))
                ]
                features.update(_behavioral_string_indicators(string_values))
            if imports:
                import_names = [
                    name
                    for imp in imports
                    if isinstance(imp, dict) and (name := _string_value(imp.get("name")))
                ]
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
            entropy_pattern = self.adapter.get_entropy_pattern()
            return entropy_pattern if isinstance(entropy_pattern, str) else ""
        return str(cmd_helper(self.adapter, self.adapter, "p=e 100"))

    def _read_head(self) -> bytes:
        return default_file_system.read_bytes(self.filepath, size=8192)
