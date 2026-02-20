#!/usr/bin/env python3
"""Cryptography detection module."""

from typing import Any, cast

from ..utils.logger import get_logger
from .crypto_constants import CRYPTO_CONSTANTS
from .crypto_domain import consolidate_detections, detect_algorithms_from_strings
from .domain_helpers import shannon_entropy
from .search_helpers import search_hex, search_text
from .string_domain import parse_search_results

logger = get_logger(__name__)


class CryptoAnalyzer:
    """Cryptographic patterns detection using a backend interface."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.r2 = adapter
        self.config = config

        self.crypto_constants = CRYPTO_CONSTANTS

    def detect(self) -> dict[str, Any]:
        """Detect cryptographic patterns and algorithms"""
        crypto_info: dict[str, Any] = {
            "algorithms": [],
            "constants": [],
            "entropy_analysis": {},
            "suspicious_patterns": [],
        }

        try:
            # Detect crypto constants
            crypto_info["constants"] = self._detect_crypto_constants()

            # Detect algorithms from strings
            crypto_info["algorithms"] = self._detect_crypto_algorithms()

            # Analyze entropy
            crypto_info["entropy_analysis"] = self._analyze_entropy()

            # Find suspicious patterns
            crypto_info["suspicious_patterns"] = self._find_suspicious_patterns()

        except Exception as e:
            logger.error(f"Error in crypto detection: {e}")
            crypto_info["error"] = str(e)

        return crypto_info

    def _detect_crypto_constants(self) -> list[dict[str, Any]]:
        """Search for known cryptographic constants"""
        found_constants = []

        try:
            for const_name, const_values in self.crypto_constants.items():
                for value in const_values:
                    if isinstance(value, int):
                        # Search for 32-bit integer constants
                        hex_value = f"{value:08x}"
                        result = self._search_hex(hex_value)

                        if result and result.strip():
                            found_constants.append(
                                {
                                    "type": const_name,
                                    "value": hex(value),
                                    "addresses": self._parse_search_results(result),
                                }
                            )

        except Exception as e:
            logger.error(f"Error detecting crypto constants: {e}")

        return found_constants

    def _detect_crypto_apis(self) -> list[dict[str, Any]]:
        """Detect cryptographic API calls"""
        crypto_apis = []

        try:
            imports = self._get_imports()

            if imports:
                # Modern BCrypt/CNG APIs (Windows Vista+)
                bcrypt_apis = {
                    "BCryptOpenAlgorithmProvider": "BCrypt",
                    "BCryptCreateHash": "Hash",
                    "BCryptEncrypt": "BCrypt",
                    "BCryptDecrypt": "BCrypt",
                    "BCryptGenerateKeyPair": "BCrypt",
                    "NCryptCreatePersistedKey": "CNG",
                    "NCryptEncrypt": "CNG",
                }

                # Legacy CryptoAPI
                cryptoapi_apis = {
                    "CryptAcquireContext": "CryptoAPI",
                    "CryptCreateHash": "Hash",
                    "CryptHashData": "Hash",
                    "CryptEncrypt": "CryptoAPI",
                    "CryptDecrypt": "CryptoAPI",
                    "CryptGenKey": "CryptoAPI",
                    "CryptDeriveKey": "CryptoAPI",
                }

                # OpenSSL APIs
                openssl_apis = {
                    "EVP_EncryptInit": "OpenSSL",
                    "EVP_DecryptInit": "OpenSSL",
                    "AES_encrypt": "AES",
                    "AES_decrypt": "AES",
                    "RSA_public_encrypt": "RSA",
                    "RSA_private_decrypt": "RSA",
                    "MD5_Init": "MD5",
                    "SHA1_Init": "SHA1",
                    "SHA256_Init": "SHA256",
                }

                all_apis = {**bcrypt_apis, **cryptoapi_apis, **openssl_apis}

                for imp in imports:
                    func_name = imp.get("name", "")
                    for api_name, algo_type in all_apis.items():
                        if api_name in func_name:
                            crypto_apis.append(
                                {
                                    "function": func_name,
                                    "algorithm": algo_type,
                                    "library": imp.get("libname", "unknown"),
                                    "address": hex(imp.get("plt", 0)),
                                }
                            )

        except Exception as e:
            logger.error(f"Error detecting crypto APIs: {e}")

        return crypto_apis

    def _detect_via_api_calls(self, detected_algos: dict[str, list]) -> None:
        """Detect crypto via API imports (highest confidence)"""
        crypto_apis = self._detect_crypto_apis()
        for api_info in crypto_apis:
            algo_name = api_info["algorithm"]
            if algo_name not in detected_algos:
                detected_algos[algo_name] = []
            detected_algos[algo_name].append(
                {
                    "evidence_type": "API Call",
                    "evidence": api_info["function"],
                    "confidence": 0.9,
                    "address": api_info["address"],
                }
            )

    def _detect_via_constants(self, detected_algos: dict[str, list]) -> None:
        """Detect crypto via cryptographic constants (high confidence)"""
        constants = self._detect_crypto_constants()
        algo_map = {
            "aes_sbox": "AES",
            "md5_h": "MD5",
            "sha1_h": "SHA1",
            "sha256_k": "SHA256",
            "des_sbox": "DES",
        }

        for const_info in constants:
            algo_name = algo_map.get(const_info["type"])
            if algo_name:
                if algo_name not in detected_algos:
                    detected_algos[algo_name] = []
                detected_algos[algo_name].append(
                    {
                        "evidence_type": "Crypto Constant",
                        "evidence": f"{const_info['type']}: {const_info['value']}",
                        "confidence": 0.8,
                        "address": (
                            const_info["addresses"][0] if const_info["addresses"] else "N/A"
                        ),
                    }
                )

    def _detect_via_strings(self, detected_algos: dict[str, list]) -> None:
        """Detect crypto via string patterns (lower confidence)"""
        strings_result = self._get_strings()
        if not strings_result:
            return
        detect_algorithms_from_strings(strings_result, detected_algos)

    def _detect_crypto_algorithms(self) -> list[dict[str, Any]]:
        """Detect crypto algorithms from strings and API calls with confidence scoring"""
        detected_algos: dict[str, list] = {}

        try:
            # Detect via API calls (highest confidence)
            self._detect_via_api_calls(detected_algos)

            # Detect via crypto constants (high confidence)
            self._detect_via_constants(detected_algos)

            # Detect via string patterns (lower confidence)
            self._detect_via_strings(detected_algos)

            # Consolidate and return results
            return consolidate_detections(detected_algos)

        except Exception as e:
            logger.error(f"Error detecting crypto algorithms: {e}")
            return []

    def _analyze_entropy(self) -> dict[str, Any]:
        """Analyze entropy of different sections"""
        entropy_info = {}

        try:
            sections = self._get_sections()

            if sections:
                for section in sections:
                    section_name = section.get("name", "unknown")
                    section_size = section.get("size", 0)

                    if section_size > 0:
                        # Calculate entropy for this section
                        entropy = self._calculate_section_entropy(section)
                        entropy_info[section_name] = {
                            "entropy": entropy,
                            "size": section_size,
                            "suspicious": entropy > 7.0,  # High entropy threshold
                        }

        except Exception as e:
            logger.error(f"Error analyzing entropy: {e}")

        return entropy_info

    def _calculate_section_entropy(self, section: dict[str, Any]) -> float:
        """Calculate entropy for a section."""
        try:
            vaddr = section.get("vaddr", 0)
            size = section.get("size", 0)

            if size == 0:
                return 0.0

            hex_data = self._read_bytes(vaddr, size).hex() if size else ""

            if not hex_data:
                return 0.0

            # Convert hex to bytes
            try:
                data = bytes.fromhex(hex_data)
            except ValueError:
                return 0.0

            if len(data) == 0:  # pragma: no cover
                return 0.0  # pragma: no cover
            return shannon_entropy(data)

        except Exception as e:
            logger.error(f"Error calculating section entropy: {e}")
            return 0.0

    def _find_suspicious_patterns(self) -> list[dict[str, Any]]:
        """Find patterns that might indicate crypto/packing"""
        patterns = []

        try:
            # Look for XOR loops (common in crypto and packing)
            xor_patterns = self._search_text("xor")
            if xor_patterns and xor_patterns.strip():
                patterns.append(
                    {
                        "type": "XOR Operations",
                        "description": "Multiple XOR operations found",
                        "evidence": "XOR instructions detected",
                    }
                )

            # Look for bit rotation operations
            rot_patterns = self._search_text("rol,ror")
            if rot_patterns and rot_patterns.strip():
                patterns.append(
                    {
                        "type": "Bit Rotation",
                        "description": "Bit rotation operations found",
                        "evidence": "ROL/ROR instructions detected",
                    }
                )

            # Look for table lookups (S-boxes)
            # This is a simplified check
            mov_patterns = self._search_text("mov.*\\[.*\\\\+.*\\]")
            if mov_patterns and mov_patterns.strip():
                count = len(mov_patterns.strip().split("\n"))
                if count > 10:  # Threshold for table lookups
                    patterns.append(
                        {
                            "type": "Table Lookups",
                            "description": f"Multiple table lookup patterns found ({count})",
                            "evidence": "Array/table access patterns",
                        }
                    )

        except Exception as e:
            logger.error(f"Error finding suspicious patterns: {e}")

        return patterns

    def _parse_search_results(self, result: str) -> list[str]:
        """Parse radare2 search results."""
        return parse_search_results(result)

    @staticmethod
    def _coerce_dict_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _get_imports(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_imports"):
            return self._coerce_dict_list(self.adapter.get_imports())
        return []

    def _get_sections(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_sections"):
            return self._coerce_dict_list(self.adapter.get_sections())
        return []

    def _get_strings(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_strings"):
            return self._coerce_dict_list(self.adapter.get_strings())
        return []

    def _search_text(self, pattern: str) -> str:
        return search_text(self.adapter, self.r2, pattern)

    def _search_hex(self, hex_pattern: str) -> str:
        return search_hex(self.adapter, self.r2, hex_pattern)

    def _read_bytes(self, vaddr: int, size: int) -> bytes:
        if self.adapter is not None and hasattr(self.adapter, "read_bytes"):
            return cast(bytes, self.adapter.read_bytes(vaddr, size))
        return b""

    def detect_crypto_libraries(self) -> list[dict[str, Any]]:
        """Detect crypto libraries by import analysis"""
        crypto_libs = []

        try:
            imports = self._get_imports()

            if imports:
                crypto_api_patterns = {
                    "Windows CryptoAPI": [
                        "CryptCreateHash",
                        "CryptHashData",
                        "CryptDeriveKey",
                        "CryptEncrypt",
                        "CryptDecrypt",
                        "CryptGenKey",
                    ],
                    "OpenSSL": [
                        "EVP_EncryptInit",
                        "EVP_DecryptInit",
                        "SSL_new",
                        "RSA_generate_key",
                        "AES_encrypt",
                    ],
                    "BCrypt": [
                        "BCryptCreateHash",
                        "BCryptHashData",
                        "BCryptFinishHash",
                        "BCryptGenerateSymmetricKey",
                        "BCryptEncrypt",
                    ],
                }

                for imp in imports:
                    imp_name = imp.get("name", "")

                    for lib_name, api_list in crypto_api_patterns.items():
                        if any(api in imp_name for api in api_list):
                            crypto_libs.append(
                                {
                                    "library": lib_name,
                                    "api_function": imp_name,
                                    "address": hex(imp.get("plt", 0)),
                                }
                            )

        except Exception as e:
            logger.error(f"Error detecting crypto libraries: {e}")

        return crypto_libs
