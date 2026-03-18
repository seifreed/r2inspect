"""Helpers for bindiff feature extraction and comparison."""

from __future__ import annotations

import hashlib
from typing import Any


def build_analysis(analyzer: Any, logger: Any) -> dict[str, Any]:
    logger.debug("Starting binary diff analysis for %s", analyzer.filename)
    results = {
        "filename": analyzer.filename,
        "filepath": analyzer.filepath,
        "structural_features": analyzer._extract_structural_features(),
        "function_features": analyzer._extract_function_features(),
        "string_features": analyzer._extract_string_features(),
        "byte_features": analyzer._extract_byte_features(),
        "behavioral_features": analyzer._extract_behavioral_features(),
        "comparison_ready": True,
    }
    results["signatures"] = analyzer._generate_comparison_signatures(results)
    logger.debug("Binary diff analysis completed for %s", analyzer.filename)
    return results


def compare_with_results(analyzer: Any, other_results: dict[str, Any]) -> dict[str, Any]:
    our_results = analyzer.analyze()
    if not our_results.get("comparison_ready") or not other_results.get("comparison_ready"):
        return {
            "error": "One or both binaries are not ready for comparison",
            "similarity_score": 0.0,
        }
    comparison = {
        "binary_a": our_results["filename"],
        "binary_b": other_results["filename"],
        "structural_similarity": analyzer._compare_structural(our_results, other_results),
        "function_similarity": analyzer._compare_functions(our_results, other_results),
        "string_similarity": analyzer._compare_strings(our_results, other_results),
        "byte_similarity": analyzer._compare_bytes(our_results, other_results),
        "behavioral_similarity": analyzer._compare_behavioral(our_results, other_results),
    }
    overall_score = analyzer._calculate_overall_similarity(comparison)
    comparison["overall_similarity"] = overall_score
    comparison["similarity_level"] = analyzer._categorize_similarity(overall_score)
    return comparison


def extract_structural_features(analyzer: Any, logger: Any) -> dict[str, Any]:
    features: dict[str, Any] = {}
    try:
        file_info = analyzer.adapter.get_file_info() if analyzer.adapter else {}
        if file_info:
            features["file_type"] = file_info.get("core", {}).get("format", "")
            features["architecture"] = file_info.get("bin", {}).get("arch", "")
            features["bits"] = file_info.get("bin", {}).get("bits", 0)
            features["endian"] = file_info.get("bin", {}).get("endian", "")
            features["file_size"] = file_info.get("core", {}).get("size", 0)
        sections = analyzer.adapter.get_sections() if analyzer.adapter else []
        if sections:
            features["section_count"] = len(sections)
            features["section_names"] = sorted(
                [s.get("name", "") for s in sections if s.get("name")]
            )
            features["section_sizes"] = [s.get("size", 0) for s in sections]
            features["executable_sections"] = len([s for s in sections if "x" in s.get("perm", "")])
            features["writable_sections"] = len([s for s in sections if "w" in s.get("perm", "")])
        imports = analyzer.adapter.get_imports() if analyzer.adapter else []
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
        exports = analyzer.adapter.get_exports() if analyzer.adapter else []
        if exports:
            features["export_count"] = len(exports)
            features["exported_functions"] = [
                exp.get("name", "") for exp in exports if exp.get("name")
            ]
    except Exception as exc:
        logger.debug("Error extracting structural features: %s", exc)
    return features


def extract_function_features(analyzer: Any, logger: Any) -> dict[str, Any]:
    features: dict[str, Any] = {}
    try:
        if analyzer.adapter and hasattr(analyzer.adapter, "analyze_all"):
            analyzer.adapter.analyze_all()
        else:
            analyzer._run_analysis_command()
        functions = analyzer.adapter.get_functions() if analyzer.adapter else []
        if functions:
            features["function_count"] = len(functions)
            features["function_sizes"] = [f.get("size", 0) for f in functions]
            features["function_names"] = [f.get("name", "") for f in functions if f.get("name")]
            cfg_features = []
            for func in functions[:10]:
                func_addr = func.get("offset", 0)
                if func_addr:
                    cfg = analyzer.adapter.get_cfg(func_addr) if analyzer.adapter else {}
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
                                "complexity": analyzer._calculate_cyclomatic_complexity(cfg_data),
                            }
                        )
            features["cfg_features"] = cfg_features
    except Exception as exc:
        logger.debug("Error extracting function features: %s", exc)
    return features


def extract_string_features(analyzer: Any, logger: Any) -> dict[str, Any]:
    features: dict[str, Any] = {}
    try:
        strings = analyzer.adapter.get_strings() if analyzer.adapter else []
        if strings:
            string_values = [s.get("string", "") for s in strings if s.get("string")]
            features["total_strings"] = len(string_values)
            features["unique_strings"] = len(set(string_values))
            features["string_lengths"] = [len(s) for s in string_values]
            api_strings = [s for s in string_values if analyzer._is_api_string(s)]
            path_strings = [s for s in string_values if analyzer._is_path_string(s)]
            url_strings = [s for s in string_values if analyzer._is_url_string(s)]
            registry_strings = [s for s in string_values if analyzer._is_registry_string(s)]
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


def extract_byte_features(analyzer: Any, logger: Any) -> dict[str, Any]:
    features: dict[str, Any] = {}
    try:
        entropy_info = analyzer._get_entropy_pattern()
        if entropy_info:
            features["entropy_pattern"] = entropy_info.strip()
        try:
            data = analyzer._read_file_head()
            if data:
                features["rolling_hash"] = analyzer._calculate_rolling_hash(data)
        except Exception as exc:
            logger.debug("Failed to compute rolling hash: %s", exc)
    except Exception as exc:
        logger.debug("Error extracting byte features: %s", exc)
    return features


def extract_behavioral_features(analyzer: Any, logger: Any) -> dict[str, Any]:
    features: dict[str, Any] = {}
    try:
        strings = analyzer.adapter.get_strings() if analyzer.adapter else []
        imports = analyzer.adapter.get_imports() if analyzer.adapter else []
        if strings:
            string_values = [s.get("string", "") for s in strings if s.get("string")]
            features["crypto_indicators"] = len(
                [s for s in string_values if analyzer._has_crypto_indicators(s)]
            )
            features["network_indicators"] = len(
                [s for s in string_values if analyzer._has_network_indicators(s)]
            )
            features["persistence_indicators"] = len(
                [s for s in string_values if analyzer._has_persistence_indicators(s)]
            )
        if imports:
            import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
            features["suspicious_apis"] = len(
                [api for api in import_names if analyzer._is_suspicious_api(api)]
            )
            features["crypto_apis"] = len(
                [api for api in import_names if analyzer._is_crypto_api(api)]
            )
            features["network_apis"] = len(
                [api for api in import_names if analyzer._is_network_api(api)]
            )
    except Exception as exc:
        logger.debug("Error extracting behavioral features: %s", exc)
    return features


def generate_signatures(results: dict[str, Any], analyzer: Any, logger: Any) -> dict[str, str]:
    signatures = {}
    try:
        signatures["structural"] = hashlib.md5(
            analyzer._build_struct_signature(results.get("structural_features", {})).encode(),
            usedforsecurity=False,
        ).hexdigest()
        signatures["function"] = hashlib.md5(
            analyzer._build_function_signature(results.get("function_features", {})).encode(),
            usedforsecurity=False,
        ).hexdigest()
        signatures["string"] = hashlib.md5(
            analyzer._build_string_signature(results.get("string_features", {})).encode(),
            usedforsecurity=False,
        ).hexdigest()
        signatures["behavioral"] = hashlib.md5(
            analyzer._build_behavioral_signature(results.get("behavioral_features", {})).encode(),
            usedforsecurity=False,
        ).hexdigest()
    except Exception as exc:
        logger.debug("Error generating signatures: %s", exc)
    return signatures
