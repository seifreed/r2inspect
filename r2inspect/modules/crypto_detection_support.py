"""Helpers for crypto detection orchestration and evidence extraction."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from ..abstractions.coercion_support import coerce_int
from ..domain.text_helpers import has_text


class CryptoHost(Protocol):
    """Overridable collaboration contract the crypto-detection helpers depend on."""

    crypto_constants: dict[str, Any]

    def _detect_crypto_constants(self) -> list[dict[str, Any]]: ...
    def _detect_crypto_algorithms(self) -> list[dict[str, Any]]: ...
    def _analyze_entropy(self) -> dict[str, Any]: ...
    def _find_suspicious_patterns(self) -> list[dict[str, Any]]: ...
    def _calculate_section_entropy(self, section: dict[str, Any]) -> float: ...
    def _parse_search_results(self, result: str) -> list[str]: ...
    def _get_imports(self) -> list[dict[str, Any]]: ...
    def _get_sections(self) -> list[dict[str, Any]]: ...
    def _search_text(self, pattern: str) -> str: ...
    def _search_hex(self, hex_pattern: str) -> str: ...


def build_crypto_report(analyzer: CryptoHost) -> dict[str, Any]:
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


def _crypto_search_patterns(values: list[int]) -> list[tuple[str, str]]:
    """Build (hex-pattern, value-repr) pairs to feed r2's /x for a constant set.

    Two real-binary layouts, neither of which the old per-value 4-byte
    big-endian search could match:
    - S-box tables (AES/DES) are contiguous bytes, so the whole sequence is one
      pattern, not each entry zero-padded to 8 hex digits.
    - 32-bit word constants (hash init vectors / round constants) are stored
      little-endian in memory, so each word is searched little-endian.
    """
    if values and all(0 <= value < 0x100 for value in values):
        pattern = "".join(f"{value:02x}" for value in values)
        return [(pattern, "0x" + pattern)]
    patterns: list[tuple[str, str]] = []
    for value in values:
        if value < 0:
            continue
        width = max(4, (value.bit_length() + 7) // 8)
        patterns.append((value.to_bytes(width, "little").hex(), hex(value)))
    return patterns


def detect_crypto_constants(analyzer: CryptoHost, logger: logging.Logger) -> list[dict[str, Any]]:
    found_constants: list[dict[str, Any]] = []
    try:
        if not isinstance(analyzer.crypto_constants, dict):
            return found_constants
        for const_name, const_values in analyzer.crypto_constants.items():
            if isinstance(const_values, (dict, str, bytes)):
                continue
            try:
                const_source = list(const_values)
            except TypeError:
                continue
            values: list[int] = []
            for value in const_source:
                try:
                    values.append(int(value, 0) if isinstance(value, str) else int(value))
                except (TypeError, ValueError):
                    continue
            for pattern, value_repr in _crypto_search_patterns(values):
                result = analyzer._search_hex(pattern)
                if has_text(result):
                    found_constants.append(
                        {
                            "type": const_name,
                            "value": value_repr,
                            "addresses": analyzer._parse_search_results(result),
                        }
                    )
    except Exception as exc:
        logger.error("Error detecting crypto constants: %s", exc)
    return found_constants


def detect_crypto_apis(analyzer: CryptoHost, logger: logging.Logger) -> list[dict[str, Any]]:
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
            if not isinstance(imp, dict):
                continue
            func_name = imp.get("name", "")
            if not isinstance(func_name, str):
                continue
            for api_name, algo_type in all_apis.items():
                if api_name in func_name:
                    crypto_apis.append(
                        {
                            "function": func_name,
                            "algorithm": algo_type,
                            "library": imp.get("libname") or imp.get("library", "unknown"),
                            "address": hex(coerce_int(imp.get("plt", 0))),
                        }
                    )
    except Exception as exc:
        logger.error("Error detecting crypto APIs: %s", exc)
    return crypto_apis


def analyze_entropy(analyzer: CryptoHost, logger: logging.Logger) -> dict[str, Any]:
    entropy_info: dict[str, Any] = {}
    try:
        sections = analyzer._get_sections()
        if sections:
            for section in sections:
                if not isinstance(section, dict):
                    continue
                section_name_value = section.get("name", "unknown")
                section_name = (
                    section_name_value if isinstance(section_name_value, str) else "unknown"
                )
                section_size = coerce_int(section.get("size", 0))
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


def find_suspicious_patterns(analyzer: CryptoHost, logger: logging.Logger) -> list[dict[str, Any]]:
    patterns: list[dict[str, Any]] = []
    try:
        xor_patterns = analyzer._search_text("xor")
        if has_text(xor_patterns):
            patterns.append(
                {
                    "type": "XOR Operations",
                    "description": "Multiple XOR operations found",
                    "evidence": "XOR instructions detected",
                }
            )
        # search_text runs r2's /aa (case-insensitive substring match on the
        # disassembly), so a comma-joined "rol,ror" matches no instruction; the
        # two mnemonics must be searched separately.
        rot_patterns = analyzer._search_text("rol") or analyzer._search_text("ror")
        if has_text(rot_patterns):
            patterns.append(
                {
                    "type": "Bit Rotation",
                    "description": "Bit rotation operations found",
                    "evidence": "ROL/ROR instructions detected",
                }
            )
    except Exception as exc:
        logger.error("Error finding suspicious patterns: %s", exc)
    return patterns


def detect_crypto_libraries(analyzer: CryptoHost, logger: logging.Logger) -> list[dict[str, Any]]:
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
            if not isinstance(imp, dict):
                continue
            imp_name = imp.get("name", "")
            if not isinstance(imp_name, str):
                continue
            for lib_name, api_list in crypto_api_patterns.items():
                if any(api in imp_name for api in api_list):
                    crypto_libs.append(
                        {
                            "library": lib_name,
                            "api_function": imp_name,
                            "address": hex(coerce_int(imp.get("plt", 0))),
                        }
                    )
    except Exception as exc:
        logger.error("Error detecting crypto libraries: %s", exc)
    return crypto_libs
