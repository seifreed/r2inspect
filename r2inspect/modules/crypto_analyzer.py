#!/usr/bin/env python3
"""
Cryptography Detection Module using r2pipe
"""

import math
import re
from typing import Any

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class CryptoAnalyzer:
    """Cryptographic patterns detection using radare2"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config

        # Known crypto constants
        self.crypto_constants = {
            # AES S-Box
            "aes_sbox": [
                0x63,
                0x7C,
                0x77,
                0x7B,
                0xF2,
                0x6B,
                0x6F,
                0xC5,
                0x30,
                0x01,
                0x67,
                0x2B,
                0xFE,
                0xD7,
                0xAB,
                0x76,
            ],
            # MD5 constants
            "md5_h": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            # SHA1 constants
            "sha1_h": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            # SHA256 constants
            "sha256_k": [
                0x428A2F98,
                0x71374491,
                0xB5C0FBCF,
                0xE9B5DBA5,
                0x3956C25B,
                0x59F111F1,
                0x923F82A4,
                0xAB1C5ED5,
            ],
            # DES S-boxes indicators
            "des_sbox": [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            # RSA common exponents
            "rsa_exponents": [3, 17, 65537],
        }

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
                        search_cmd = f"/x {hex_value}"
                        result = safe_cmd(self.r2, search_cmd)

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
            # Get imports
            imports = safe_cmdj(self.r2, "iij")

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
        strings_result = safe_cmdj(self.r2, "izj")
        if not strings_result:
            return

        crypto_patterns = {
            "AES": [
                r"\baes\b",
                r"\brijndael\b",
                r"advanced.encryption.standard",
                r"aes[_-]?(128|192|256)",
                r"aes[_-]?cbc",
                r"aes[_-]?ecb",
            ],
            "DES": [r"\bdes\b", r"3des", r"triple.des", r"data.encryption.standard"],
            "RSA": [r"\brsa\b", r"rsa[_-]?key", r"public.key", r"private.key"],
            "MD5": [r"\bmd5\b", r"md5.hash", r"message.digest.5"],
            "SHA": [
                r"\bsha[_-]?1\b",
                r"\bsha[_-]?256\b",
                r"\bsha[_-]?512\b",
                r"secure.hash",
                r"sha[_-]?hash",
            ],
            "RC4": [r"\brc4\b", r"\barcfour\b"],
            "Blowfish": [r"\bblowfish\b"],
            "Base64": [r"\bbase64\b", r"base.64"],
            "OpenSSL": [r"\bopenssl\b", r"\bevp_\w+", r"ssl.ctx"],
            "BCrypt": [r"\bbcrypt\b", r"bcrypt\w+", r"cng.dll"],
            "CryptoAPI": [r"crypt32\.dll", r"advapi32\.dll", r"cryptoapi"],
        }

        noise_patterns = [
            r"vector.deleting.destructor",
            r"scalar.deleting.destructor",
            r"std::",
            r"class",
            r"struct",
            r"__",
            r"@@",
            r"\?",
            r"vtable",
        ]

        for string_info in strings_result:
            string_val = string_info.get("string", "").lower()

            # Skip noise strings
            try:
                if any(re.search(noise, string_val, re.IGNORECASE) for noise in noise_patterns):
                    continue
            except re.error as regex_error:
                logger.error(f"Regex error in noise patterns: {regex_error}")
                continue

            # Skip very short strings
            if len(string_val) < 3:
                continue

            self._match_string_to_algorithm(
                string_info, string_val, crypto_patterns, detected_algos
            )

    def _match_string_to_algorithm(
        self,
        string_info: dict[str, Any],
        string_val: str,
        crypto_patterns: dict[str, list],
        detected_algos: dict[str, list],
    ) -> None:
        """Match a string against crypto patterns and add to detected algorithms"""
        for algo_name, patterns in crypto_patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, string_val, re.IGNORECASE):
                        if algo_name not in detected_algos:
                            detected_algos[algo_name] = []
                        detected_algos[algo_name].append(
                            {
                                "evidence_type": "String Reference",
                                "evidence": string_val,
                                "confidence": 0.4,
                                "address": hex(string_info.get("vaddr", 0)),
                            }
                        )
                        return  # Found match, no need to check more patterns
                except re.error as regex_error:
                    logger.error(f"Regex error with pattern '{pattern}': {regex_error}")
                    continue

    def _consolidate_detections(self, detected_algos: dict[str, list]) -> list[dict[str, Any]]:
        """Merge and deduplicate detection results with confidence scoring"""
        algorithms = []

        for algo_name, evidences in detected_algos.items():
            # Calculate overall confidence based on evidence types
            max_confidence = max(e["confidence"] for e in evidences)
            evidence_types = {e["evidence_type"] for e in evidences}

            # Boost confidence if multiple evidence types
            if len(evidence_types) > 1:
                max_confidence = min(max_confidence + 0.2, 0.95)

            algorithms.append(
                {
                    "algorithm": algo_name,
                    "confidence": max_confidence,
                    "evidence_count": len(evidences),
                    "evidence_types": list(evidence_types),
                    "evidences": evidences[:3],  # Limit to top 3 evidences
                }
            )

        return algorithms

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
            return self._consolidate_detections(detected_algos)

        except Exception as e:
            logger.error(f"Error detecting crypto algorithms: {e}")
            return []

    def _analyze_entropy(self) -> dict[str, Any]:
        """Analyze entropy of different sections"""
        entropy_info = {}

        try:
            # Get sections information
            sections = safe_cmdj(self.r2, "iSj")

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
        """Calculate entropy for a section"""
        try:
            vaddr = section.get("vaddr", 0)
            size = section.get("size", 0)

            if size == 0:
                return 0.0

            # Read section data
            data_cmd = f"p8 {size} @ {vaddr}"
            hex_data = safe_cmd(self.r2, data_cmd)

            if not hex_data:
                return 0.0

            # Convert hex to bytes
            try:
                data = bytes.fromhex(hex_data)
            except ValueError:
                return 0.0

            # Calculate entropy
            if len(data) == 0:
                return 0.0

            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy using Shannon entropy formula: -Σ(p * log2(p))
            entropy = 0.0
            data_len = len(data)

            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)

            return entropy

        except Exception as e:
            logger.error(f"Error calculating section entropy: {e}")
            return 0.0

    def _find_suspicious_patterns(self) -> list[dict[str, Any]]:
        """Find patterns that might indicate crypto/packing"""
        patterns = []

        try:
            # Look for XOR loops (common in crypto and packing)
            xor_patterns = safe_cmd(self.r2, "/c xor")
            if xor_patterns and xor_patterns.strip():
                patterns.append(
                    {
                        "type": "XOR Operations",
                        "description": "Multiple XOR operations found",
                        "evidence": "XOR instructions detected",
                    }
                )

            # Look for bit rotation operations
            rot_patterns = safe_cmd(self.r2, "/c rol,ror")
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
            mov_patterns = safe_cmd(self.r2, "/c mov.*\\[.*\\\\+.*\\]")
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
        """Parse radare2 search results"""
        addresses = []

        lines = result.strip().split("\n")
        for line in lines:
            if line.startswith("0x"):
                addr = line.split()[0]
                addresses.append(addr)

        return addresses

    def detect_crypto_libraries(self) -> list[dict[str, Any]]:
        """Detect crypto libraries by import analysis"""
        crypto_libs = []

        try:
            # Get imports
            imports = safe_cmdj(self.r2, "iij")

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
