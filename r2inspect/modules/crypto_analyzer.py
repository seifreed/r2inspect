#!/usr/bin/env python3
"""Cryptography detection module."""

from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from .crypto_detection_support import (
    analyze_entropy as build_entropy_analysis,
    build_crypto_report,
    detect_crypto_apis as find_crypto_apis,
    detect_crypto_constants as find_crypto_constants,
    detect_crypto_libraries as find_crypto_libraries,
    find_suspicious_patterns as build_suspicious_patterns,
)
from .crypto_constants import CRYPTO_CONSTANTS
from ..domain.formats.crypto import consolidate_detections, detect_algorithms_from_strings
from .domain_helpers import shannon_entropy
from .search_helpers import search_hex, search_text
from ..domain.formats.string import parse_search_results

logger = get_logger(__name__)


class CryptoAnalyzer(CommandHelperMixin):
    """Cryptographic patterns detection using a backend interface."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.config = config
        self.crypto_constants = CRYPTO_CONSTANTS

    def analyze(self) -> dict[str, Any]:
        """Unified entry point for pipeline dispatch."""
        return self.detect()

    def detect(self) -> dict[str, Any]:
        """Detect cryptographic patterns and algorithms."""
        return self._safe_call(
            lambda: build_crypto_report(self),
            default={
                "algorithms": [],
                "constants": [],
                "entropy_analysis": {},
                "suspicious_patterns": [],
            },
            error_msg="Error in crypto detection",
        )

    def _detect_crypto_constants(self) -> list[dict[str, Any]]:
        return find_crypto_constants(self, logger)

    def _detect_crypto_apis(self) -> list[dict[str, Any]]:
        return find_crypto_apis(self, logger)

    def _detect_via_api_calls(self, detected_algos: dict[str, list]) -> None:
        """Detect crypto via API imports (highest confidence)."""
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
        """Detect crypto via cryptographic constants (high confidence)."""
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
        """Detect crypto via string patterns (lower confidence)."""
        strings_result = self._get_strings()
        if strings_result:
            detect_algorithms_from_strings(strings_result, detected_algos)

    def _run_all_detections(self) -> list[dict[str, Any]]:
        """Coordinate all crypto-detection strategies and consolidate results."""
        detected_algos: dict[str, list] = {}
        self._detect_via_api_calls(detected_algos)
        self._detect_via_constants(detected_algos)
        self._detect_via_strings(detected_algos)
        return consolidate_detections(detected_algos)

    def _detect_crypto_algorithms(self) -> list[dict[str, Any]]:
        """Detect crypto algorithms from strings and API calls with confidence scoring."""
        return self._safe_call(
            self._run_all_detections,
            default=[],
            error_msg="Error detecting crypto algorithms",
        )

    def _analyze_entropy(self) -> dict[str, Any]:
        return build_entropy_analysis(self, logger)

    def _do_calculate_section_entropy(self, section: dict[str, Any]) -> float:
        vaddr = section.get("vaddr", 0)
        size = section.get("size", 0)
        if size == 0:
            return 0.0
        hex_data = self._read_bytes(vaddr, size).hex() if size else ""
        if not hex_data:
            return 0.0
        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            return 0.0
        return shannon_entropy(data) if data else 0.0

    def _calculate_section_entropy(self, section: dict[str, Any]) -> float:
        """Calculate entropy for a section."""
        return self._safe_call(
            lambda: self._do_calculate_section_entropy(section),
            default=0.0,
            error_msg="Error calculating section entropy",
        )

    def _find_suspicious_patterns(self) -> list[dict[str, Any]]:
        return build_suspicious_patterns(self, logger)

    def _parse_search_results(self, result: str) -> list[str]:
        return parse_search_results(result)

    def _get_imports(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_imports") or [])

    def _get_sections(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_sections") or [])

    def _get_strings(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_strings") or [])

    def _search_text(self, pattern: str) -> str:
        return search_text(self.adapter, pattern)

    def _search_hex(self, hex_pattern: str) -> str:
        return search_hex(self.adapter, hex_pattern)

    def _read_bytes(self, vaddr: int, size: int) -> bytes:
        if self.adapter is not None and hasattr(self.adapter, "read_bytes"):
            return cast(bytes, self.adapter.read_bytes(vaddr, size))
        return b""

    def detect_crypto_libraries(self) -> list[dict[str, Any]]:
        return find_crypto_libraries(self, logger)
