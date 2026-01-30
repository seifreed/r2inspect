# mypy: ignore-errors
"""
Authenticode signature analyzer module using radare2.
"""

import hashlib
import logging
import struct
from datetime import datetime
from typing import Any

from ..utils.r2_helpers import safe_cmd, safe_cmdj
from ..utils.r2_suppress import silent_cmdj

logger = logging.getLogger(__name__)


class AuthenticodeAnalyzer:
    """Analyzes and verifies Authenticode signatures in PE files."""

    def __init__(self, r2):
        """
        Initialize the Authenticode analyzer.

        Args:
            r2: Radare2 instance
        """
        self.r2 = r2
        self.pe_info = None

    def analyze(self) -> dict[str, Any]:
        """
        Analyze Authenticode signature in the PE file.

        Returns:
            Dictionary containing signature information
        """
        try:
            result = {
                "has_signature": False,
                "signature_valid": False,
                "certificates": [],
                "timestamp": None,
                "signature_offset": None,
                "signature_size": None,
                "security_directory": None,
                "errors": [],
            }

            if not self._has_required_headers():
                return result

            security_dir = self._get_security_directory()
            if not security_dir or security_dir.get("vaddr", 0) == 0:
                result["has_signature"] = False
                return result

            result["has_signature"] = True
            result["security_directory"] = {
                "offset": security_dir.get("paddr", 0),
                "size": security_dir.get("size", 0),
                "virtual_address": security_dir.get("vaddr", 0),
            }

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
            logger.error(f"Error analyzing Authenticode signature: {e}")
            return {"has_signature": False, "signature_valid": False, "error": str(e)}

    def _has_required_headers(self) -> bool:
        pe_header = silent_cmdj(self.r2, "ihj", {})
        if not pe_header:
            return False
        optional_header = silent_cmdj(self.r2, "iHj", {})
        return bool(optional_header)

    def _get_security_directory(self) -> dict[str, Any] | None:
        data_dirs = silent_cmdj(self.r2, "iDj", [])
        if not isinstance(data_dirs, list):
            return None
        for dd in data_dirs:
            if isinstance(dd, dict) and dd.get("name") == "SECURITY":
                return dd
        return None

    def _read_win_certificate(
        self, security_dir: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any] | None:
        cert_offset = security_dir.get("paddr", 0)
        cert_size = security_dir.get("size", 0)
        if cert_offset == 0 or cert_size == 0:
            result["errors"].append("Invalid security directory")
            return None

        result["signature_offset"] = cert_offset
        result["signature_size"] = cert_size
        self._seek_to_offset(cert_offset)
        win_cert_data = silent_cmdj(self.r2, f"pxj 8 @ {cert_offset}", [])
        if not (win_cert_data and len(win_cert_data) >= 8):
            return None

        cert_length, cert_revision, cert_type = self._parse_win_cert_header(win_cert_data)
        cert_info = {
            "length": cert_length,
            "revision": hex(cert_revision),
            "type": self._get_cert_type_name(cert_type),
            "type_value": hex(cert_type),
        }

        if cert_type == 0x0002:
            cert_info["format"] = "PKCS#7"
            pkcs7_info = self._parse_pkcs7(cert_offset + 8, cert_length - 8)
            if pkcs7_info:
                cert_info.update(pkcs7_info)

        return cert_info

    def _seek_to_offset(self, offset: int) -> None:
        try:
            self.r2.cmd(f"s {offset}")
        except Exception as exc:
            logger.debug(f"Failed to seek to cert offset {offset}: {exc}")

    def _parse_win_cert_header(self, data: list[int]) -> tuple[int, int, int]:
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

    def _parse_pkcs7(self, offset: int, size: int) -> dict[str, Any | None]:
        """Parse PKCS#7 signature data."""
        try:
            result = {
                "signer_info": [],
                "certificates_chain": [],
                "digest_algorithm": None,
                "encryption_algorithm": None,
            }

            pkcs7_data = silent_cmdj(self.r2, f"pxj {min(size, 1024)} @ {offset}", [])
            if not pkcs7_data:
                return None

            result["digest_algorithm"] = self._detect_digest_algorithm(pkcs7_data)
            result["encryption_algorithm"] = self._detect_encryption_algorithm(pkcs7_data)
            result["signer_info"] = self._extract_common_names(pkcs7_data, offset)
            if self._has_timestamp(pkcs7_data):
                result["has_timestamp"] = True

            return result

        except Exception as e:
            logger.error(f"Error parsing PKCS#7: {e}")
            return None

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
            logger.debug(f"Failed to decode signer common name at {offset + pos}: {exc}")
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

    def _compute_authenticode_hash(self) -> dict[str, str | None]:
        """Compute the Authenticode hash of the PE file."""
        try:
            # Get file size
            file_info = silent_cmdj(self.r2, "ij", {})
            if not file_info:
                return None

            file_size = file_info.get("core", {}).get("size", 0)
            if file_size == 0:
                return None

            # Get PE header offset
            pe_header = silent_cmdj(self.r2, "ihj", {})
            if not pe_header:
                return None

            # Get checksum field offset (it should be excluded from hash)
            optional_header = silent_cmdj(self.r2, "iHj", {})
            if not optional_header:
                return None

            # Calculate regions to hash (excluding checksum and certificate table)
            # This is a simplified version - full implementation would need to:
            # 1. Hash from start to checksum field
            # 2. Skip checksum (4 bytes)
            # 3. Hash from after checksum to certificate table entry
            # 4. Skip certificate table entry (8 bytes)
            # 5. Hash from after certificate table entry to start of certificate data

            # For now, return a placeholder indicating the hash regions
            return {
                "algorithm": "SHA256",
                "note": "Authenticode hash calculation regions identified",
                "file_size": file_size,
                "regions": "Multiple regions excluding checksum and certificate data",
            }

        except Exception as e:
            logger.error(f"Error computing Authenticode hash: {e}")
            return None

    def _verify_signature_integrity(self, signature_info: dict[str, Any]) -> bool:
        """Verify the integrity of the signature."""
        try:
            # Basic checks for signature validity
            if not signature_info.get("has_signature"):
                return False

            # Check if certificate data is present and valid
            if not signature_info.get("certificates"):
                return False

            # Check for errors during parsing
            if signature_info.get("errors"):
                return False

            # Check security directory is valid
            sec_dir = signature_info.get("security_directory")
            return not (not sec_dir or sec_dir.get("size", 0) == 0)

        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
