"""Helpers for crypto detection orchestration and evidence extraction."""

from __future__ import annotations

from typing import Any


def build_crypto_report(analyzer: Any) -> dict[str, Any]:
    crypto_info: dict[str, Any] = {
        "algorithms": [],
        "constants": [],
        "entropy_analysis": {},
        "suspicious_patterns": [],
    }
    crypto_info["constants"] = analyzer._detect_crypto_constants()
    crypto_info["algorithms"] = analyzer._detect_crypto_algorithms()
    crypto_info["entropy_analysis"] = analyzer._analyze_entropy()
    crypto_info["suspicious_patterns"] = analyzer._find_suspicious_patterns()
    return crypto_info


def detect_crypto_constants(analyzer: Any, logger: Any) -> list[dict[str, Any]]:
    found_constants: list[dict[str, Any]] = []
    try:
        for const_name, const_values in analyzer.crypto_constants.items():
            for value in const_values:
                if isinstance(value, int):
                    result = analyzer._search_hex(f"{value:08x}")
                    if result and result.strip():
                        found_constants.append(
                            {
                                "type": const_name,
                                "value": hex(value),
                                "addresses": analyzer._parse_search_results(result),
                            }
                        )
    except Exception as exc:
        logger.error("Error detecting crypto constants: %s", exc)
    return found_constants


def detect_crypto_apis(analyzer: Any, logger: Any) -> list[dict[str, Any]]:
    crypto_apis: list[dict[str, Any]] = []
    try:
        imports = analyzer._get_imports()
        if not imports:
            return crypto_apis
        all_apis = {
            "BCryptOpenAlgorithmProvider": "BCrypt",
            "BCryptCreateHash": "Hash",
            "BCryptEncrypt": "BCrypt",
            "BCryptDecrypt": "BCrypt",
            "BCryptGenerateKeyPair": "BCrypt",
            "NCryptCreatePersistedKey": "CNG",
            "NCryptEncrypt": "CNG",
            "CryptAcquireContext": "CryptoAPI",
            "CryptCreateHash": "Hash",
            "CryptHashData": "Hash",
            "CryptEncrypt": "CryptoAPI",
            "CryptDecrypt": "CryptoAPI",
            "CryptGenKey": "CryptoAPI",
            "CryptDeriveKey": "CryptoAPI",
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
        for imp in imports:
            func_name = imp.get("name", "")
            for api_name, algo_type in all_apis.items():
                if api_name in func_name:
                    crypto_apis.append(
                        {
                            "function": func_name,
                            "algorithm": algo_type,
                            "library": imp.get("libname") or imp.get("library", "unknown"),
                            "address": hex(imp.get("plt", 0)),
                        }
                    )
    except Exception as exc:
        logger.error("Error detecting crypto APIs: %s", exc)
    return crypto_apis


def analyze_entropy(analyzer: Any, logger: Any) -> dict[str, Any]:
    entropy_info: dict[str, Any] = {}
    try:
        sections = analyzer._get_sections()
        if sections:
            for section in sections:
                section_name = section.get("name", "unknown")
                section_size = section.get("size", 0)
                if section_size > 0:
                    entropy = analyzer._calculate_section_entropy(section)
                    entropy_info[section_name] = {
                        "entropy": entropy,
                        "size": section_size,
                        "suspicious": entropy > 7.0,
                    }
    except Exception as exc:
        logger.error("Error analyzing entropy: %s", exc)
    return entropy_info


def find_suspicious_patterns(analyzer: Any, logger: Any) -> list[dict[str, Any]]:
    patterns: list[dict[str, Any]] = []
    try:
        xor_patterns = analyzer._search_text("xor")
        if xor_patterns and xor_patterns.strip():
            patterns.append(
                {
                    "type": "XOR Operations",
                    "description": "Multiple XOR operations found",
                    "evidence": "XOR instructions detected",
                }
            )
        rot_patterns = analyzer._search_text("rol,ror")
        if rot_patterns and rot_patterns.strip():
            patterns.append(
                {
                    "type": "Bit Rotation",
                    "description": "Bit rotation operations found",
                    "evidence": "ROL/ROR instructions detected",
                }
            )
        mov_patterns = analyzer._search_text("mov.*\\[.*\\\\+.*\\]")
        if mov_patterns and mov_patterns.strip():
            count = len(mov_patterns.strip().split("\n"))
            if count > 10:
                patterns.append(
                    {
                        "type": "Table Lookups",
                        "description": f"Multiple table lookup patterns found ({count})",
                        "evidence": "Array/table access patterns",
                    }
                )
    except Exception as exc:
        logger.error("Error finding suspicious patterns: %s", exc)
    return patterns


def detect_crypto_libraries(analyzer: Any, logger: Any) -> list[dict[str, Any]]:
    crypto_libs: list[dict[str, Any]] = []
    try:
        imports = analyzer._get_imports()
        if not imports:
            return crypto_libs
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
    except Exception as exc:
        logger.error("Error detecting crypto libraries: %s", exc)
    return crypto_libs
