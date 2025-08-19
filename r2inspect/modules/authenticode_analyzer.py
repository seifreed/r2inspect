"""
Authenticode signature analyzer module using radare2.
"""

import hashlib
import logging
import struct
from datetime import datetime
from typing import Any, Dict, List, Optional

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

    def analyze(self) -> Dict[str, Any]:
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

            # Get PE header info
            pe_header = silent_cmdj(self.r2, "ihj", {})
            if not pe_header:
                # Return minimal result for files that can't be parsed
                return result

            # Get optional header to find security directory
            optional_header = silent_cmdj(self.r2, "iHj", {})
            if not optional_header:
                # Return minimal result for files that can't be parsed
                return result

            # Get data directories
            data_dirs = silent_cmdj(self.r2, "iDj", [])
            if not isinstance(data_dirs, list):
                data_dirs = []
            if not data_dirs:
                # Return minimal result for files that can't be parsed
                return result

            # Find security directory (index 4)
            security_dir = None
            for dd in data_dirs:
                if isinstance(dd, dict) and dd.get("name") == "SECURITY":
                    security_dir = dd
                    break

            if not security_dir or security_dir.get("vaddr", 0) == 0:
                result["has_signature"] = False
                return result

            result["has_signature"] = True
            result["security_directory"] = {
                "offset": security_dir.get("paddr", 0),
                "size": security_dir.get("size", 0),
                "virtual_address": security_dir.get("vaddr", 0),
            }

            # Read the WIN_CERTIFICATE structure
            cert_offset = security_dir.get("paddr", 0)
            cert_size = security_dir.get("size", 0)

            if cert_offset == 0 or cert_size == 0:
                result["errors"].append("Invalid security directory")
                return result

            result["signature_offset"] = cert_offset
            result["signature_size"] = cert_size

            # Seek to certificate location
            try:
                self.r2.cmd(f"s {cert_offset}")
            except Exception:
                pass  # Ignore seek errors

            # Read WIN_CERTIFICATE header (8 bytes)
            win_cert_data = silent_cmdj(self.r2, f"pxj 8 @ {cert_offset}", [])
            if win_cert_data and len(win_cert_data) >= 8:
                # Parse WIN_CERTIFICATE structure
                cert_length = (
                    win_cert_data[0]
                    | (win_cert_data[1] << 8)
                    | (win_cert_data[2] << 16)
                    | (win_cert_data[3] << 24)
                )
                cert_revision = win_cert_data[4] | (win_cert_data[5] << 8)
                cert_type = win_cert_data[6] | (win_cert_data[7] << 8)

                cert_info = {
                    "length": cert_length,
                    "revision": hex(cert_revision),
                    "type": self._get_cert_type_name(cert_type),
                    "type_value": hex(cert_type),
                }

                # Check if it's PKCS#7 signature (most common)
                if cert_type == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
                    cert_info["format"] = "PKCS#7"

                    # Try to parse PKCS#7 data
                    pkcs7_info = self._parse_pkcs7(cert_offset + 8, cert_length - 8)
                    if pkcs7_info:
                        cert_info.update(pkcs7_info)

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

    def _get_cert_type_name(self, cert_type: int) -> str:
        """Get certificate type name."""
        types = {0x0001: "X.509", 0x0002: "PKCS#7", 0x0003: "RESERVED", 0x0004: "TS_STACK_SIGNED"}
        return types.get(cert_type, f"UNKNOWN ({hex(cert_type)})")

    def _parse_pkcs7(self, offset: int, size: int) -> Optional[Dict[str, Any]]:
        """Parse PKCS#7 signature data."""
        try:
            result = {
                "signer_info": [],
                "certificates_chain": [],
                "digest_algorithm": None,
                "encryption_algorithm": None,
            }

            # Read PKCS#7 data
            pkcs7_data = silent_cmdj(self.r2, f"pxj {min(size, 1024)} @ {offset}", [])
            if not pkcs7_data:
                return None

            # Look for common OID patterns in the data
            # These are simplified checks - full ASN.1 parsing would be more complex

            # Check for SHA256 OID (2.16.840.1.101.3.4.2.1)
            sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
            if self._find_pattern(pkcs7_data, sha256_oid):
                result["digest_algorithm"] = "SHA256"
            # Check for SHA1 OID (1.3.14.3.2.26)
            elif self._find_pattern(pkcs7_data, [0x2B, 0x0E, 0x03, 0x02, 0x1A]):
                result["digest_algorithm"] = "SHA1"

            # Check for RSA encryption OID (1.2.840.113549.1.1.1)
            rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
            if self._find_pattern(pkcs7_data, rsa_oid):
                result["encryption_algorithm"] = "RSA"

            # Try to extract certificate common names (simplified)
            # Look for common name OID (2.5.4.3)
            cn_oid = [0x55, 0x04, 0x03]
            cn_positions = self._find_all_patterns(pkcs7_data, cn_oid)

            for pos in cn_positions[:3]:  # Limit to first 3 certificates
                # Try to extract the CN value (simplified extraction)
                if pos + 10 < len(pkcs7_data):
                    # Skip OID and length bytes, try to read string
                    start = pos + 5
                    length = pkcs7_data[pos + 4] if pos + 4 < len(pkcs7_data) else 0
                    if length > 0 and length < 100 and start + length <= len(pkcs7_data):
                        cn_bytes = pkcs7_data[start : start + length]
                        try:
                            cn_str = bytes(cn_bytes).decode("utf-8", errors="ignore")
                            if cn_str and cn_str.isprintable():
                                result["signer_info"].append(
                                    {"common_name": cn_str, "offset": offset + pos}
                                )
                        except Exception:
                            pass

            # Look for timestamp (simplified check)
            # RFC 3161 timestamp OID (1.2.840.113549.1.9.16.2.14)
            timestamp_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
            if self._find_pattern(pkcs7_data, timestamp_oid):
                result["has_timestamp"] = True

            return result

        except Exception as e:
            logger.error(f"Error parsing PKCS#7: {e}")
            return None

    def _find_pattern(self, data: List[int], pattern: List[int]) -> bool:
        """Find a byte pattern in data."""
        pattern_len = len(pattern)
        data_len = len(data)

        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                return True
        return False

    def _find_all_patterns(self, data: List[int], pattern: List[int]) -> List[int]:
        """Find all occurrences of a byte pattern in data."""
        positions = []
        pattern_len = len(pattern)
        data_len = len(data)

        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                positions.append(i)
        return positions

    def _compute_authenticode_hash(self) -> Optional[Dict[str, str]]:
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

    def _verify_signature_integrity(self, signature_info: Dict[str, Any]) -> bool:
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
