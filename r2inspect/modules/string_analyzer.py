#!/usr/bin/env python3
"""
String Analysis Module using r2pipe
"""

import base64
import binascii
import re
from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list

logger = get_logger(__name__)


class StringAnalyzer(BaseAnalyzer):
    """String extraction and analysis using radare2"""

    def __init__(self, r2, config):
        super().__init__(r2=r2, config=config)
        self.min_length = config.get("strings", "min_length", 4)
        self.max_length = config.get("strings", "max_length", 100)
        self.max_strings = config.get("general", "max_strings", 1000)

    def get_category(self) -> str:
        return "metadata"

    def get_description(self) -> str:
        return "Extracts and analyzes strings from binary files including ASCII, Unicode, and encoded strings"

    def analyze(self) -> dict[str, Any]:
        """Perform string analysis"""
        result = self._init_result_structure(
            {
                "total_strings": 0,
                "strings": [],
                "suspicious_strings": [],
                "decoded_strings": [],
                "statistics": {},
            }
        )

        try:
            self._log_info("Starting string analysis")
            strings = self.extract_strings()
            result["strings"] = strings
            result["total_strings"] = len(strings)
            result["available"] = True
            self._log_info(f"Extracted {len(strings)} strings")
        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"String analysis failed: {e}")

        return result

    def extract_strings(self) -> list[str]:
        """Extract strings from binary"""
        strings = []

        try:
            # Extract ASCII strings
            if self.config.get("strings", "extract_ascii", True):
                ascii_strings = self._extract_ascii_strings()
                strings.extend(ascii_strings)

            # Extract Unicode strings
            if self.config.get("strings", "extract_unicode", True):
                unicode_strings = self._extract_unicode_strings()
                strings.extend(unicode_strings)

            # Remove duplicates and filter
            strings = list(set(strings))
            strings = self._filter_strings(strings)

            # Limit number of strings
            if len(strings) > self.max_strings:
                strings = strings[: self.max_strings]

        except Exception as e:
            logger.error(f"Error extracting strings: {e}")

        return strings

    def _extract_ascii_strings(self) -> list[str]:
        """Extract ASCII strings using radare2"""
        strings = []

        try:
            # Use radare2 strings command
            result = safe_cmd_list(self.r2, "izj")

            if result:
                for string_info in result:
                    string_val = string_info.get("string", "")
                    if string_val and len(string_val) >= self.min_length:
                        strings.append(string_val)

        except Exception as e:
            logger.error(f"Error extracting ASCII strings: {e}")

        return strings

    def _extract_unicode_strings(self) -> list[str]:
        """Extract Unicode strings using radare2"""
        strings = []

        try:
            # Use radare2 Unicode strings command
            result = safe_cmd_list(self.r2, "izuj")

            if result:
                for string_info in result:
                    string_val = string_info.get("string", "")
                    if string_val and len(string_val) >= self.min_length:
                        strings.append(string_val)

        except Exception as e:
            logger.error(f"Error extracting Unicode strings: {e}")

        return strings

    def _filter_strings(self, strings: list[str]) -> list[str]:
        """Filter and clean strings"""
        filtered = []

        for string in strings:
            # Length filter
            if len(string) < self.min_length or len(string) > self.max_length:
                continue

            # Remove non-printable characters
            cleaned = "".join(c for c in string if c.isprintable())
            if len(cleaned) >= self.min_length:
                filtered.append(cleaned)

        return filtered

    def search_xor(self, search_string: str) -> list[dict[str, Any]]:
        """Search for XOR'd strings"""
        matches = []

        try:
            # Try different XOR keys (0-255)
            for key in range(1, 256):
                xor_result = self._xor_string(search_string, key)

                # Search for the XOR'd string in binary
                search_cmd = f"/x {xor_result.encode().hex()}"
                result = self.r2.cmd(search_cmd)

                if result and result.strip():
                    matches.append(
                        {
                            "original_string": search_string,
                            "xor_key": key,
                            "xor_result": xor_result,
                            "addresses": self._parse_search_results(result),
                        }
                    )

        except Exception as e:
            logger.error(f"Error in XOR search: {e}")

        return matches

    def _xor_string(self, text: str, key: int) -> str:
        """XOR a string with a single byte key"""
        return "".join(chr(ord(c) ^ key) for c in text)

    def _parse_search_results(self, result: str) -> list[str]:
        """Parse radare2 search results"""
        addresses = []

        lines = result.strip().split("\n")
        for line in lines:
            if line.startswith("0x"):
                addr = line.split()[0]
                addresses.append(addr)

        return addresses

    def get_suspicious_strings(self) -> list[dict[str, Any]]:
        """Find suspicious strings that might indicate malware"""
        suspicious = []
        strings = self.extract_strings()

        # Suspicious patterns
        patterns = {
            "urls": r"https?://[^\s]+",
            "ips": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "registry": r"HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-]+",
            "files": r"[A-Za-z]:\\[\\A-Za-z0-9_\-\.]+\.[A-Za-z]{2,4}",
            "api_calls": r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary)",
            "crypto": r"(AES|DES|RSA|MD5|SHA1|SHA256|RC4)",
            "mutex": r"(Global\\|Local\\)[A-Za-z0-9_\-]+",
            "base64": r"[A-Za-z0-9+/]{20,}={0,2}",
        }

        for string in strings:
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, string, re.IGNORECASE)
                if matches:
                    suspicious.append({"string": string, "type": pattern_name, "matches": matches})

        return suspicious

    def decode_strings(self) -> list[dict[str, Any]]:
        """Attempt to decode encoded strings"""
        decoded = []
        strings = self.extract_strings()

        for string in strings:
            decoded_entry = self._decode_base64(string)
            if decoded_entry:
                decoded.append(decoded_entry)

            decoded_entry = self._decode_hex(string)
            if decoded_entry:
                decoded.append(decoded_entry)

        return decoded

    def _decode_base64(self, string: str) -> dict[str, Any] | None:
        if not self._is_base64(string):
            return None
        try:
            decoded_bytes = base64.b64decode(string)
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded_str and decoded_str.isprintable():
                return {
                    "original": string,
                    "decoded": decoded_str,
                    "encoding": "base64",
                }
        except (UnicodeDecodeError, binascii.Error):
            return None
        return None

    def _decode_hex(self, string: str) -> dict[str, Any] | None:
        if not self._is_hex(string):
            return None
        try:
            decoded_bytes = bytes.fromhex(string)
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded_str and decoded_str.isprintable():
                return {
                    "original": string,
                    "decoded": decoded_str,
                    "encoding": "hex",
                }
        except UnicodeDecodeError:
            return None
        return None

    def _is_base64(self, s: str) -> bool:
        """Check if string looks like base64"""
        if len(s) < 8 or len(s) % 4 != 0:
            return False
        try:
            return base64.b64encode(base64.b64decode(s)).decode() == s
        except (UnicodeDecodeError, binascii.Error):
            return False

    def _is_hex(self, s: str) -> bool:
        """Check if string looks like hex"""
        if len(s) < 8 or len(s) % 2 != 0:
            return False
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    def get_string_statistics(self) -> dict[str, Any]:
        """Get statistics about extracted strings"""
        strings = self.extract_strings()

        stats = {
            "total_strings": len(strings),
            "avg_length": sum(len(s) for s in strings) / len(strings) if strings else 0,
            "min_length": min(len(s) for s in strings) if strings else 0,
            "max_length": max(len(s) for s in strings) if strings else 0,
            "charset_analysis": self._analyze_charset(strings),
        }

        return stats

    def _analyze_charset(self, strings: list[str]) -> dict[str, int]:
        """Analyze character sets used in strings"""
        charset_count = {"ascii": 0, "unicode": 0, "printable": 0, "alphanumeric": 0}

        for string in strings:
            if all(ord(c) < 128 for c in string):
                charset_count["ascii"] += 1
            else:
                charset_count["unicode"] += 1

            if string.isprintable():
                charset_count["printable"] += 1

            if string.isalnum():
                charset_count["alphanumeric"] += 1

        return charset_count
