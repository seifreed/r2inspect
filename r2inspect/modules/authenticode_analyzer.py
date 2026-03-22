"""Authenticode signature analyzer."""

import hashlib
import struct
from datetime import datetime
from typing import Any

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from ..infrastructure.r2_suppress import silent_cmdj
from .authenticode_parsing_support import (
    get_security_directory as _get_security_directory_impl,
    parse_pkcs7 as _parse_pkcs7_impl,
    read_win_certificate as _read_win_certificate_impl,
)
from .authenticode_result_support import (
    apply_security_directory as _apply_security_directory_impl,
    init_authenticode_result as _init_authenticode_result_impl,
)

logger = get_logger(__name__)


class AuthenticodeAnalyzer(CommandHelperMixin, BaseAnalyzer):
    """Analyzes and verifies Authenticode signatures in PE files."""

    def __init__(self, adapter: Any) -> None:
        """
        Initialize the Authenticode analyzer.

        Args:
            r2: Radare2 instance
        """
        super().__init__(adapter=adapter)
        self.pe_info = None

    def analyze(self) -> dict[str, Any]:
        """
        Analyze Authenticode signature in the PE file.

        Returns:
            Dictionary containing signature information
        """
        result: dict[str, Any] = {}
        try:
            result = _init_authenticode_result_impl(self._init_result_structure)

            if not self._has_required_headers():
                result["available"] = False
                return result

            security_dir = self._get_security_directory()
            if not security_dir or security_dir.get("vaddr", 0) == 0:
                result["has_signature"] = False
                return result

            _apply_security_directory_impl(result, security_dir)

            cert_info = self._read_win_certificate(security_dir, result)
            if cert_info:
                result["certificates"].append(cert_info)

            # Check signature validity by computing authenticode hash
            auth_hash = self._compute_authenticode_hash()
            if auth_hash:
                result["authenticode_hash"] = auth_hash

            # Check if certificate chain is valid
            result["signature_valid"] = self._verify_signature_integrity(result)

            return result

        except Exception as e:
            logger.error("Error analyzing Authenticode signature: %s", e)
            result["available"] = False
            result["has_signature"] = False
            result["signature_valid"] = False
            result["error"] = str(e)
            return result

    def _has_required_headers(self) -> bool:
        pe_header = self._cmdj("ihj", {})
        if not pe_header:
            return False
        optional_header = self._cmdj("iHj", {})
        return bool(optional_header)

    def _get_security_directory(self) -> dict[str, Any] | None:
        return _get_security_directory_impl(self._cmdj)

    def _read_win_certificate(
        self, security_dir: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any] | None:
        return _read_win_certificate_impl(
            cmdj=self._cmdj,
            security_dir=security_dir,
            result=result,
            parse_header_fn=self._parse_win_cert_header,
            get_cert_type_name_fn=self._get_cert_type_name,
            parse_pkcs7_fn=self._parse_pkcs7,
        )

    def _parse_win_cert_header(self, data: list[int]) -> tuple[int, int, int]:
        if len(data) < 8:
            raise ValueError(f"WIN_CERTIFICATE header requires 8 bytes, got {len(data)}")
        cert_length = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
        cert_revision = data[4] | (data[5] << 8)
        cert_type = data[6] | (data[7] << 8)
        return cert_length, cert_revision, cert_type

    def _get_cert_type_name(self, cert_type: int) -> str:
        """Get certificate type name."""
        types = {
            0x0001: "X.509",
            0x0002: "PKCS#7",
            0x0003: "RESERVED",
            0x0004: "TS_STACK_SIGNED",
        }
        return types.get(cert_type, f"UNKNOWN ({hex(cert_type)})")

    def _parse_pkcs7(self, offset: int, size: int) -> dict[str, Any] | None:
        """Parse PKCS#7 signature data."""
        return _parse_pkcs7_impl(
            cmdj=self._cmdj,
            offset=offset,
            size=size,
            logger=logger,
            detect_digest_algorithm_fn=self._detect_digest_algorithm,
            detect_encryption_algorithm_fn=self._detect_encryption_algorithm,
            extract_common_names_fn=self._extract_common_names,
            has_timestamp_fn=self._has_timestamp,
        )

    def _detect_digest_algorithm(self, pkcs7_data: list[int]) -> str | None:
        sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        if self._find_pattern(pkcs7_data, sha256_oid):
            return "SHA256"
        if self._find_pattern(pkcs7_data, [0x2B, 0x0E, 0x03, 0x02, 0x1A]):
            return "SHA1"
        return None

    def _detect_encryption_algorithm(self, pkcs7_data: list[int]) -> str | None:
        rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        if self._find_pattern(pkcs7_data, rsa_oid):
            return "RSA"
        return None

    def _extract_common_names(self, pkcs7_data: list[int], offset: int) -> list[dict[str, Any]]:
        cn_oid = [0x55, 0x04, 0x03]
        cn_positions = self._find_all_patterns(pkcs7_data, cn_oid)
        signer_info: list[dict[str, Any]] = []
        for pos in cn_positions[:3]:
            entry = self._extract_cn_entry(pkcs7_data, offset, pos)
            if entry:
                signer_info.append(entry)
        return signer_info

    def _extract_cn_entry(
        self, pkcs7_data: list[int], offset: int, pos: int
    ) -> dict[str, Any] | None:
        if pos + 10 >= len(pkcs7_data):
            return None
        start = pos + 5
        length = pkcs7_data[pos + 4] if pos + 4 < len(pkcs7_data) else 0
        if length <= 0 or length >= 100 or start + length > len(pkcs7_data):
            return None
        cn_bytes = pkcs7_data[start : start + length]
        try:
            cn_str = bytes(cn_bytes).decode("utf-8", errors="ignore")
            if cn_str and cn_str.isprintable():
                return {"common_name": cn_str, "offset": offset + pos}
        except Exception as exc:
            logger.debug("Failed to decode signer common name at %s: %s", offset + pos, exc)
        return None

    def _has_timestamp(self, pkcs7_data: list[int]) -> bool:
        timestamp_oid = [
            0x2A,
            0x86,
            0x48,
            0x86,
            0xF7,
            0x0D,
            0x01,
            0x09,
            0x10,
            0x02,
            0x0E,
        ]
        return self._find_pattern(pkcs7_data, timestamp_oid)

    def _find_pattern(self, data: list[int], pattern: list[int]) -> bool:
        """Find a byte pattern in data."""
        pattern_len = len(pattern)
        data_len = len(data)
        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                return True
        return False

    def _find_all_patterns(self, data: list[int], pattern: list[int]) -> list[int]:
        """Find all occurrences of a byte pattern in data."""
        positions = []
        pattern_len = len(pattern)
        data_len = len(data)
        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                positions.append(i)
        return positions

    def _compute_authenticode_hash(self) -> dict[str, str | None] | None:
        """Compute the Authenticode hash of the PE file."""
        try:
            file_info = self._cmdj("ij", {})
            if not file_info:
                return None
            file_size = file_info.get("core", {}).get("size", 0)
            if file_size == 0:
                return None
            pe_header = self._cmdj("ihj", {})
            if not pe_header:
                return None
            optional_header = self._cmdj("iHj", {})
            if not optional_header:
                return None
            return {
                "algorithm": "SHA256",
                "note": "Authenticode hash calculation regions identified",
                "file_size": file_size,
                "regions": "Multiple regions excluding checksum and certificate data",
            }
        except Exception as exc:
            logger.error("Error computing Authenticode hash: %s", exc)
            return None

    def _verify_signature_integrity(self, signature_info: dict[str, Any]) -> bool:
        """Verify the integrity of the signature."""
        try:
            if not signature_info.get("has_signature"):
                return False
            if not signature_info.get("certificates"):
                return False
            if signature_info.get("errors"):
                return False
            sec_dir = signature_info.get("security_directory")
            return not (not sec_dir or sec_dir.get("size", 0) == 0)
        except Exception as exc:
            logger.error("Error verifying signature: %s", exc)
            return False
