#!/usr/bin/env python3
# mypy: ignore-errors
"""
Binary Diff Analyzer Module

This module implements binary diffing and comparison analysis to identify similarities
and differences between malware samples. It's useful for:

- Malware family identification and clustering
- Variant analysis and evolution tracking
- Code reuse detection across samples
- Attribution analysis for threat actor identification
- Patch diffing to identify security fixes

The module provides multiple comparison techniques:
1. Structural comparison (sections, headers, imports)
2. Function-level comparison using CFG similarity
3. String-based similarity analysis
4. Byte-level similarity using rolling hashes
5. Behavioral pattern comparison

Based on BinDiff and similar binary comparison tools.
"""

import hashlib
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)


class BinDiffAnalyzer:
    """Binary diffing and comparison analyzer"""

    def __init__(self, r2, filepath: str):
        self.r2 = r2
        self.filepath = filepath
        self.filename = Path(filepath).name

    def analyze(self) -> dict[str, Any]:
        """Perform binary diffing analysis"""
        try:
            logger.debug(f"Starting binary diff analysis for {self.filename}")

            results = {
                "filename": self.filename,
                "filepath": self.filepath,
                "structural_features": self._extract_structural_features(),
                "function_features": self._extract_function_features(),
                "string_features": self._extract_string_features(),
                "byte_features": self._extract_byte_features(),
                "behavioral_features": self._extract_behavioral_features(),
                "comparison_ready": True,
            }

            # Generate comparison signatures
            results["signatures"] = self._generate_comparison_signatures(results)

            logger.debug(f"Binary diff analysis completed for {self.filename}")
            return results

        except Exception as e:
            logger.error(f"Error in binary diff analysis for {self.filename}: {e}")
            return {
                "filename": self.filename,
                "filepath": self.filepath,
                "error": str(e),
                "comparison_ready": False,
            }

    def compare_with(self, other_results: dict[str, Any]) -> dict[str, Any]:
        """Compare this binary with another binary's analysis results"""
        try:
            # Get our own analysis results first
            our_results = self.analyze()

            if not our_results.get("comparison_ready") or not other_results.get("comparison_ready"):
                return {
                    "error": "One or both binaries are not ready for comparison",
                    "similarity_score": 0.0,
                }

            comparison = {
                "binary_a": our_results["filename"],
                "binary_b": other_results["filename"],
                "structural_similarity": self._compare_structural(our_results, other_results),
                "function_similarity": self._compare_functions(our_results, other_results),
                "string_similarity": self._compare_strings(our_results, other_results),
                "byte_similarity": self._compare_bytes(our_results, other_results),
                "behavioral_similarity": self._compare_behavioral(our_results, other_results),
            }

            # Calculate overall similarity score
            weights = {
                "structural": 0.2,
                "function": 0.3,
                "string": 0.2,
                "byte": 0.15,
                "behavioral": 0.15,
            }

            overall_score = (
                comparison["structural_similarity"] * weights["structural"]
                + comparison["function_similarity"] * weights["function"]
                + comparison["string_similarity"] * weights["string"]
                + comparison["byte_similarity"] * weights["byte"]
                + comparison["behavioral_similarity"] * weights["behavioral"]
            )

            comparison["overall_similarity"] = round(overall_score, 3)
            comparison["similarity_level"] = self._categorize_similarity(overall_score)

            return comparison

        except Exception as e:
            logger.error(f"Error comparing binaries: {e}")
            return {"error": str(e), "similarity_score": 0.0}

    def _extract_structural_features(self) -> dict[str, Any]:
        """Extract structural features for comparison"""
        features = {}

        try:
            # Get file info
            file_info = safe_cmdj(self.r2, "ij", {})
            if file_info:
                features["file_type"] = file_info.get("core", {}).get("format", "")
                features["architecture"] = file_info.get("bin", {}).get("arch", "")
                features["bits"] = file_info.get("bin", {}).get("bits", 0)
                features["endian"] = file_info.get("bin", {}).get("endian", "")
                features["file_size"] = file_info.get("core", {}).get("size", 0)

            # Get sections info
            sections = safe_cmdj(self.r2, "iSj", [])
            if sections:
                features["section_count"] = len(sections)
                features["section_names"] = sorted(
                    [s.get("name", "") for s in sections if s.get("name")]
                )
                features["section_sizes"] = [s.get("size", 0) for s in sections]
                features["executable_sections"] = len(
                    [s for s in sections if s.get("perm", "").find("x") != -1]
                )
                features["writable_sections"] = len(
                    [s for s in sections if s.get("perm", "").find("w") != -1]
                )

            # Get imports info
            imports = safe_cmdj(self.r2, "iij", [])
            if imports:
                features["import_count"] = len(imports)
                features["imported_dlls"] = list(
                    {imp.get("libname", "") for imp in imports if imp.get("libname")}
                )
                features["imported_functions"] = [
                    imp.get("name", "") for imp in imports if imp.get("name")
                ]

            # Get exports info
            exports = safe_cmdj(self.r2, "iEj", [])
            if exports:
                features["export_count"] = len(exports)
                features["exported_functions"] = [
                    exp.get("name", "") for exp in exports if exp.get("name")
                ]

        except Exception as e:
            logger.debug(f"Error extracting structural features: {e}")

        return features

    def _extract_function_features(self) -> dict[str, Any]:
        """Extract function-level features for comparison"""
        features = {}

        try:
            # Analyze functions
            self.r2.cmd("aaa")  # Analyze all

            # Get function list
            functions = safe_cmdj(self.r2, "aflj", [])
            if functions:
                features["function_count"] = len(functions)
                features["function_sizes"] = [f.get("size", 0) for f in functions]
                features["function_names"] = [f.get("name", "") for f in functions if f.get("name")]

                # Analyze a subset of functions for CFG similarity
                cfg_features = []
                for func in functions[:10]:  # Limit to first 10 functions
                    func_addr = func.get("offset", 0)
                    if func_addr:
                        self.r2.cmd(f"s {func_addr}")
                        # Force JSON output format
                        self.r2.cmd("e scr.html=false")
                        # Get control flow graph in JSON format
                        cfg = safe_cmdj(self.r2, "agj", {})
                        if cfg and isinstance(cfg, list) and cfg:
                            cfg_data = cfg[0]
                            cfg_features.append(
                                {
                                    "nodes": len(cfg_data.get("blocks", [])),
                                    "edges": len(cfg_data.get("edges", [])),
                                    "complexity": self._calculate_cyclomatic_complexity(cfg_data),
                                }
                            )

                features["cfg_features"] = cfg_features

        except Exception as e:
            logger.debug(f"Error extracting function features: {e}")

        return features

    def _extract_string_features(self) -> dict[str, Any]:
        """Extract string-based features for comparison"""
        features = {}

        try:
            # Get strings
            strings = safe_cmdj(self.r2, "izj", [])
            if strings:
                string_values = [s.get("string", "") for s in strings if s.get("string")]
                features["total_strings"] = len(string_values)
                features["string_count"] = len(string_values)  # Keep for backward compatibility
                features["unique_strings"] = len(set(string_values))
                features["string_lengths"] = [len(s) for s in string_values]

                # Categorize strings
                api_strings = [s for s in string_values if self._is_api_string(s)]
                path_strings = [s for s in string_values if self._is_path_string(s)]
                url_strings = [s for s in string_values if self._is_url_string(s)]
                registry_strings = [s for s in string_values if self._is_registry_string(s)]

                features["api_strings"] = api_strings
                features["path_strings"] = path_strings
                features["url_strings"] = url_strings
                features["registry_strings"] = registry_strings

                # Create categorized strings dictionary for CLI display
                features["categorized_strings"] = {}
                if api_strings:
                    features["categorized_strings"]["API"] = len(api_strings)
                if path_strings:
                    features["categorized_strings"]["Paths"] = len(path_strings)
                if url_strings:
                    features["categorized_strings"]["URLs"] = len(url_strings)
                if registry_strings:
                    features["categorized_strings"]["Registry"] = len(registry_strings)

                # Create string signature (hash of sorted unique strings)
                unique_sorted = sorted(set(string_values))
                features["string_signature"] = hashlib.md5(
                    "|".join(unique_sorted).encode(), usedforsecurity=False
                ).hexdigest()

        except Exception as e:
            logger.debug(f"Error extracting string features: {e}")

        return features

    def _extract_byte_features(self) -> dict[str, Any]:
        """Extract byte-level features for comparison"""
        features = {}

        try:
            # Get entropy info
            entropy_info = self.r2.cmd("p=e 100")
            if entropy_info:
                features["entropy_pattern"] = entropy_info.strip()

            # Calculate rolling hash for similarity
            try:
                with open(self.filepath, "rb") as f:
                    data = f.read(8192)  # Read first 8KB
                    if data:
                        features["rolling_hash"] = self._calculate_rolling_hash(data)
            except Exception as exc:
                logger.debug(f"Failed to compute rolling hash: {exc}")

        except Exception as e:
            logger.debug(f"Error extracting byte features: {e}")

        return features

    def _extract_behavioral_features(self) -> dict[str, Any]:
        """Extract behavioral pattern features"""
        features = {}

        try:
            # Look for common behavioral patterns in strings and imports
            strings = safe_cmdj(self.r2, "izj", [])
            imports = safe_cmdj(self.r2, "iij", [])

            if strings:
                string_values = [s.get("string", "") for s in strings if s.get("string")]
                features["crypto_indicators"] = len(
                    [s for s in string_values if self._has_crypto_indicators(s)]
                )
                features["network_indicators"] = len(
                    [s for s in string_values if self._has_network_indicators(s)]
                )
                features["persistence_indicators"] = len(
                    [s for s in string_values if self._has_persistence_indicators(s)]
                )

            if imports:
                import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
                features["suspicious_apis"] = len(
                    [api for api in import_names if self._is_suspicious_api(api)]
                )
                features["crypto_apis"] = len(
                    [api for api in import_names if self._is_crypto_api(api)]
                )
                features["network_apis"] = len(
                    [api for api in import_names if self._is_network_api(api)]
                )

        except Exception as e:
            logger.debug(f"Error extracting behavioral features: {e}")

        return features

    def _generate_comparison_signatures(self, results: dict[str, Any]) -> dict[str, str]:
        """Generate signatures for quick comparison"""
        signatures = {}

        try:
            # Structural signature
            struct_features = results.get("structural_features", {})
            struct_data = f"{struct_features.get('file_type', '')}-{struct_features.get('architecture', '')}-{len(struct_features.get('section_names', []))}"
            signatures["structural"] = hashlib.md5(
                struct_data.encode(), usedforsecurity=False
            ).hexdigest()

            # Function signature
            func_features = results.get("function_features", {})
            func_data = f"{func_features.get('function_count', 0)}-{len(func_features.get('function_names', []))}"
            signatures["function"] = hashlib.md5(
                func_data.encode(), usedforsecurity=False
            ).hexdigest()

            # String signature (already calculated)
            string_features = results.get("string_features", {})
            string_data = f"{string_features.get('total_strings', 0)}-{len(string_features.get('api_strings', []))}-{len(string_features.get('path_strings', []))}"
            signatures["string"] = hashlib.md5(
                string_data.encode(), usedforsecurity=False
            ).hexdigest()

            # Behavioral signature
            behav_features = results.get("behavioral_features", {})
            behav_data = f"{behav_features.get('crypto_indicators', 0)}-{behav_features.get('network_indicators', 0)}-{behav_features.get('suspicious_apis', 0)}"
            signatures["behavioral"] = hashlib.md5(
                behav_data.encode(), usedforsecurity=False
            ).hexdigest()

        except Exception as e:
            logger.debug(f"Error generating signatures: {e}")

        return signatures

    def _compare_structural(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare structural features between two binaries"""
        try:
            a_struct = a.get("structural_features", {})
            b_struct = b.get("structural_features", {})

            score = 0.0
            total_weight = 0.0

            # Compare file type
            if a_struct.get("file_type") == b_struct.get("file_type"):
                score += 0.2
            total_weight += 0.2

            # Compare architecture
            if a_struct.get("architecture") == b_struct.get("architecture"):
                score += 0.2
            total_weight += 0.2

            # Compare section names (Jaccard similarity)
            a_sections = set(a_struct.get("section_names", []))
            b_sections = set(b_struct.get("section_names", []))
            if a_sections or b_sections:
                jaccard = (
                    len(a_sections & b_sections) / len(a_sections | b_sections)
                    if (a_sections | b_sections)
                    else 0
                )
                score += jaccard * 0.3
            total_weight += 0.3

            # Compare import similarity
            a_imports = set(a_struct.get("imported_dlls", []))
            b_imports = set(b_struct.get("imported_dlls", []))
            if a_imports or b_imports:
                import_jaccard = (
                    len(a_imports & b_imports) / len(a_imports | b_imports)
                    if (a_imports | b_imports)
                    else 0
                )
                score += import_jaccard * 0.3
            total_weight += 0.3

            return score / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.debug(f"Error comparing structural features: {e}")
            return 0.0

    def _compare_functions(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare function-level features between two binaries"""
        try:
            a_func = a.get("function_features", {})
            b_func = b.get("function_features", {})

            score = 0.0
            total_weight = 0.0

            # Compare function count similarity
            a_count = a_func.get("function_count", 0)
            b_count = b_func.get("function_count", 0)
            if a_count > 0 and b_count > 0:
                count_sim = 1.0 - abs(a_count - b_count) / max(a_count, b_count)
                score += count_sim * 0.4
            total_weight += 0.4

            # Compare function names (Jaccard similarity)
            a_names = set(a_func.get("function_names", []))
            b_names = set(b_func.get("function_names", []))
            if a_names or b_names:
                name_jaccard = (
                    len(a_names & b_names) / len(a_names | b_names) if (a_names | b_names) else 0
                )
                score += name_jaccard * 0.6
            total_weight += 0.6

            return score / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.debug(f"Error comparing function features: {e}")
            return 0.0

    def _compare_strings(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare string-based features between two binaries"""
        try:
            a_str = a.get("string_features", {})
            b_str = b.get("string_features", {})

            # Quick signature comparison
            if a_str.get("string_signature") == b_str.get("string_signature"):
                return 1.0

            score = 0.0
            total_weight = 0.0

            # Compare API strings
            a_apis = set(a_str.get("api_strings", []))
            b_apis = set(b_str.get("api_strings", []))
            if a_apis or b_apis:
                api_jaccard = (
                    len(a_apis & b_apis) / len(a_apis | b_apis) if (a_apis | b_apis) else 0
                )
                score += api_jaccard * 0.4
            total_weight += 0.4

            # Compare path strings
            a_paths = set(a_str.get("path_strings", []))
            b_paths = set(b_str.get("path_strings", []))
            if a_paths or b_paths:
                path_jaccard = (
                    len(a_paths & b_paths) / len(a_paths | b_paths) if (a_paths | b_paths) else 0
                )
                score += path_jaccard * 0.3
            total_weight += 0.3

            # Compare registry strings
            a_reg = set(a_str.get("registry_strings", []))
            b_reg = set(b_str.get("registry_strings", []))
            if a_reg or b_reg:
                reg_jaccard = len(a_reg & b_reg) / len(a_reg | b_reg) if (a_reg | b_reg) else 0
                score += reg_jaccard * 0.3
            total_weight += 0.3

            return score / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.debug(f"Error comparing string features: {e}")
            return 0.0

    def _compare_bytes(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare byte-level features between two binaries"""
        try:
            a_bytes = a.get("byte_features", {})
            b_bytes = b.get("byte_features", {})

            score = 0.0
            total_weight = 0.0

            # Compare rolling hashes
            a_hash = a_bytes.get("rolling_hash")
            b_hash = b_bytes.get("rolling_hash")
            if a_hash and b_hash:
                hash_sim = self._compare_rolling_hashes(a_hash, b_hash)
                score += hash_sim * 1.0
            total_weight += 1.0

            return score / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.debug(f"Error comparing byte features: {e}")
            return 0.0

    def _compare_behavioral(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare behavioral features between two binaries"""
        try:
            a_behav = a.get("behavioral_features", {})
            b_behav = b.get("behavioral_features", {})

            score = 0.0
            total_weight = 0.0

            # Compare indicator counts (normalized)
            indicators = [
                "crypto_indicators",
                "network_indicators",
                "persistence_indicators",
                "suspicious_apis",
                "crypto_apis",
                "network_apis",
            ]

            for indicator in indicators:
                a_val = a_behav.get(indicator, 0)
                b_val = b_behav.get(indicator, 0)
                if a_val > 0 or b_val > 0:
                    sim = 1.0 - abs(a_val - b_val) / max(a_val, b_val, 1)
                    score += sim
                    total_weight += 1.0

            return score / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.debug(f"Error comparing behavioral features: {e}")
            return 0.0

    # Helper methods
    def _calculate_cyclomatic_complexity(self, cfg: dict[str, Any]) -> int:
        """Calculate cyclomatic complexity from CFG"""
        try:
            edges = len(cfg.get("edges", []))
            nodes = len(cfg.get("blocks", []))
            return edges - nodes + 2 if nodes > 0 else 0
        except (TypeError, AttributeError, KeyError) as e:
            logger.debug(f"Error calculating cyclomatic complexity: {e}")
            return 0

    def _calculate_rolling_hash(self, data: bytes, window_size: int = 64) -> list[int]:
        """Calculate rolling hash for byte similarity"""
        hashes = []
        for i in range(len(data) - window_size + 1):
            window = data[i : i + window_size]
            hashes.append(hash(window) & 0xFFFFFFFF)
        return hashes[:100]  # Limit to first 100 hashes

    def _compare_rolling_hashes(self, a_hashes: list[int], b_hashes: list[int]) -> float:
        """Compare rolling hashes for similarity"""
        if not a_hashes or not b_hashes:
            return 0.0

        a_set = set(a_hashes)
        b_set = set(b_hashes)
        intersection = len(a_set & b_set)
        union = len(a_set | b_set)

        return intersection / union if union > 0 else 0.0

    def _categorize_similarity(self, score: float) -> str:
        """Categorize similarity score"""
        if score >= 0.8:
            return "Very High"
        elif score >= 0.6:
            return "High"
        elif score >= 0.4:
            return "Medium"
        elif score >= 0.2:
            return "Low"
        else:
            return "Very Low"

    # String classification helpers
    def _is_api_string(self, s: str) -> bool:
        """Check if string looks like an API call"""
        api_patterns = [
            "CreateFile",
            "WriteFile",
            "ReadFile",
            "RegOpenKey",
            "GetProcAddress",
            "LoadLibrary",
            "VirtualAlloc",
            "CreateThread",
            "CreateProcess",
        ]
        return any(pattern.lower() in s.lower() for pattern in api_patterns)

    def _is_path_string(self, s: str) -> bool:
        """Check if string looks like a file path"""
        return ("\\" in s or "/" in s) and (len(s) > 3) and not s.startswith("http")

    def _is_url_string(self, s: str) -> bool:
        """Check if string looks like a URL"""
        return s.startswith(("http://", "https://", "ftp://"))

    def _is_registry_string(self, s: str) -> bool:
        """Check if string looks like a registry key"""
        reg_roots = ["HKEY_", "HKLM", "HKCU", "SOFTWARE\\", "SYSTEM\\"]
        return any(root in s.upper() for root in reg_roots)

    def _has_crypto_indicators(self, s: str) -> bool:
        """Check if string has cryptographic indicators"""
        crypto_terms = [
            "encrypt",
            "decrypt",
            "cipher",
            "hash",
            "md5",
            "sha",
            "aes",
            "rsa",
            "key",
            "crypto",
        ]
        return any(term in s.lower() for term in crypto_terms)

    def _has_network_indicators(self, s: str) -> bool:
        """Check if string has network indicators"""
        network_terms = [
            "http",
            "tcp",
            "udp",
            "socket",
            "connect",
            "download",
            "upload",
            "url",
        ]
        return any(term in s.lower() for term in network_terms)

    def _has_persistence_indicators(self, s: str) -> bool:
        """Check if string has persistence indicators"""
        persist_terms = [
            "startup",
            "autorun",
            "service",
            "registry",
            "schedule",
            "task",
        ]
        return any(term in s.lower() for term in persist_terms)

    def _is_suspicious_api(self, api: str) -> bool:
        """Check if API is commonly used by malware"""
        suspicious_apis = [
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "SetWindowsHookEx",
            "GetKeyState",
            "GetAsyncKeyState",
            "CreateService",
        ]
        return any(sus_api.lower() in api.lower() for sus_api in suspicious_apis)

    def _is_crypto_api(self, api: str) -> bool:
        """Check if API is cryptography-related"""
        crypto_apis = [
            "CryptAcquireContext",
            "CryptCreateHash",
            "CryptEncrypt",
            "CryptDecrypt",
        ]
        return any(crypto_api.lower() in api.lower() for crypto_api in crypto_apis)

    def _is_network_api(self, api: str) -> bool:
        """Check if API is network-related"""
        network_apis = [
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "InternetOpen",
            "HttpOpenRequest",
            "HttpSendRequest",
        ]
        return any(net_api.lower() in api.lower() for net_api in network_apis)
