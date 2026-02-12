#!/usr/bin/env python3
"""Rich Header analysis for PE files."""

import struct
from typing import Any, cast

from ..abstractions import BaseAnalyzer
from ..adapters.file_system import default_file_system
from ..utils.analyzer_runner import run_analyzer_on_file
from ..utils.command_helpers import cmdj as cmdj_helper
from ..utils.logger import get_logger
from .rich_header_debug import RichHeaderDebugMixin
from .rich_header_defaults import DANS_PATTERNS, RICH_PATTERNS
from .rich_header_domain import (
    build_rich_header_result,
    calculate_richpe_hash,
    decode_rich_header,
    parse_clear_data_entries,
    parse_compiler_entries,
    validate_decoded_entries,
)
from .rich_header_search import RichHeaderSearchMixin

logger = get_logger(__name__)

# Try to import pefile for better Rich Header support
try:
    import pefile

    PEFILE_AVAILABLE = True
    logger.debug("pefile library available for Rich Header analysis")
except ImportError:
    PEFILE_AVAILABLE = False
    logger.debug("pefile library not available, using r2pipe fallback")


class RichHeaderAnalyzer(RichHeaderDebugMixin, RichHeaderSearchMixin, BaseAnalyzer):
    """Rich Header extraction and analysis for PE files"""

    def __init__(
        self,
        adapter: Any | None = None,
        filepath: str | None = None,
        r2_instance: Any | None = None,
    ) -> None:
        if adapter is None:
            adapter = r2_instance
        super().__init__(adapter=adapter, filepath=filepath)

    def analyze(self) -> dict[str, Any]:
        """Run Rich Header analysis on a PE file."""
        logger.debug(f"Starting Rich Header analysis for {self.filepath}")

        results: dict[str, Any] = self._init_result_structure(
            {
                "rich_header": None,
                "compilers": [],
                "xor_key": None,
                "checksum": None,
                "richpe_hash": None,
                "error": None,
                "is_pe": False,
                "method_used": None,
            }
        )

        try:
            # Check if file is PE
            if not self._is_pe_file():
                results["error"] = "File is not a PE binary"
                logger.debug(f"File {self.filepath} is not a PE binary")
                return results

            results["is_pe"] = True
            logger.debug("File confirmed as PE binary")

            # Try pefile method first (most reliable)
            if PEFILE_AVAILABLE:
                logger.debug("Attempting Rich Header extraction using pefile library")
                rich_data = self._extract_rich_header_pefile()
                if rich_data:
                    results["method_used"] = "pefile"
                    logger.debug("Successfully extracted Rich Header using pefile")
                else:
                    logger.debug("pefile method failed, falling back to r2pipe")

            # Fall back to r2pipe method if pefile failed or not available
            if not rich_data:
                logger.debug("Attempting Rich Header extraction using r2pipe")
                rich_data = self._extract_rich_header_r2pipe()
                if rich_data:
                    results["method_used"] = "r2pipe"
                    logger.debug("Successfully extracted Rich Header using r2pipe")

            if not rich_data:
                results["error"] = "Rich Header not found"
                logger.debug("Rich Header not found with any method")
                return results

            results["available"] = True
            results["rich_header"] = rich_data
            results["xor_key"] = rich_data.get("xor_key")
            results["checksum"] = rich_data.get("checksum")

            logger.debug(
                f"Rich Header extracted successfully: XOR key=0x{rich_data.get('xor_key', 0):08x}"
            )

            # Parse compiler entries
            entries = cast(list[dict[str, Any]], rich_data.get("entries", []))
            compilers = parse_compiler_entries(entries)
            results["compilers"] = compilers
            logger.debug(f"Parsed {len(compilers)} compiler entries")

            # Calculate RichPE hash
            richpe_hash = calculate_richpe_hash(rich_data)
            if richpe_hash:
                results["richpe_hash"] = richpe_hash
                logger.debug(f"Calculated RichPE hash: {richpe_hash}")

        except Exception as e:
            logger.error(f"Rich Header analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _extract_rich_header_pefile(self) -> dict[str, Any] | None:
        """Extract Rich Header using pefile when available."""
        if not PEFILE_AVAILABLE:
            return None

        pe = None
        try:
            pe = pefile.PE(self.filepath)
            if not self._pefile_has_rich_header(pe):
                logger.debug("No Rich Header found by pefile")
                return None

            rich_hash = pe.get_rich_header_hash()
            if not rich_hash:
                logger.debug("Could not calculate Rich Header hash with pefile")
                return None

            logger.debug(f"pefile calculated Rich Header hash: {rich_hash}")
            xor_key = self._pefile_get_xor_key(pe)
            entries = self._pefile_extract_entries(pe)
            if not entries:
                entries = self._pefile_entries_from_clear_data(pe)

            return self._build_pefile_rich_result(pe, xor_key, entries, rich_hash)

        except Exception as e:
            logger.debug(f"pefile Rich Header extraction failed: {e}")
            return None
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception as exc:
                    logger.debug(f"Failed to close pefile handle: {exc}")

    def _pefile_has_rich_header(self, pe: Any) -> bool:
        """Check if pefile exposes a Rich Header."""
        return hasattr(pe, "RICH_HEADER") and bool(pe.RICH_HEADER)

    def _pefile_get_xor_key(self, pe: Any) -> int | None:
        """Get XOR key/checksum from pefile Rich Header."""
        return pe.RICH_HEADER.checksum if hasattr(pe.RICH_HEADER, "checksum") else None

    def _pefile_extract_entries(self, pe: Any) -> list[dict[str, Any]]:
        """Extract Rich Header entries from pefile RICH_HEADER.values."""
        entries: list[dict[str, Any]] = []
        if not hasattr(pe.RICH_HEADER, "values") or not pe.RICH_HEADER.values:
            return entries
        for entry in pe.RICH_HEADER.values:
            parsed = self._pefile_parse_entry(entry)
            if parsed:
                entries.append(parsed)
        return entries

    def _pefile_parse_entry(self, entry: Any) -> dict[str, Any] | None:
        """Parse a pefile Rich Header entry into our schema."""
        if not (
            hasattr(entry, "product_id")
            and hasattr(entry, "build_version")
            and hasattr(entry, "count")
        ):
            return None
        prodid = entry.product_id | (entry.build_version << 16)
        return {
            "product_id": entry.product_id,
            "build_number": entry.build_version,
            "count": entry.count,
            "prodid": prodid,
        }

    def _pefile_entries_from_clear_data(self, pe: Any) -> list[dict[str, Any]]:
        """Fallback: parse entries from pefile clear_data."""
        if not hasattr(pe.RICH_HEADER, "clear_data"):
            return []
        return parse_clear_data_entries(pe.RICH_HEADER.clear_data)

    def _build_pefile_rich_result(
        self,
        pe: Any,
        xor_key: int | None,
        entries: list[dict[str, Any]],
        rich_hash: str,
    ) -> dict[str, Any]:
        """Build Rich Header result dictionary from pefile fields."""
        return {
            "xor_key": xor_key,
            "checksum": xor_key,
            "entries": entries,
            "richpe_hash": rich_hash,
            "clear_data": (
                pe.RICH_HEADER.clear_data.hex() if hasattr(pe.RICH_HEADER, "clear_data") else None
            ),
            "method": "pefile",
            "clear_data_bytes": (
                pe.RICH_HEADER.clear_data if hasattr(pe.RICH_HEADER, "clear_data") else None
            ),
        }

    def _extract_rich_header_r2pipe(self) -> dict[str, Any] | None:
        """
        Extract Rich Header using r2pipe (fallback method).

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            # Extract Rich Header with detailed debugging
            rich_data = self._extract_rich_header()
            if not rich_data:
                # Try additional debugging
                logger.debug("Standard extraction failed, trying hex dump analysis...")
                self._debug_file_structure()
                return None

            return rich_data

        except Exception as e:
            logger.error(f"r2pipe Rich Header extraction failed: {e}")
            return None

    def _is_pe_file(self) -> bool:
        """
        Check if the file is a PE binary.

        Returns:
            True if file is PE, False otherwise
        """
        try:
            if not self.r2:
                logger.error("r2 instance is None")
                return False

            if self._check_magic_bytes():
                return True

            if self._check_info_command():
                return True

            return self._check_bin_info()

        except Exception as e:
            logger.error(f"Error checking if file is PE: {e}")
            return False

    def _check_magic_bytes(self) -> bool:
        """Check file magic bytes for MZ header."""
        try:
            if not self.filepath:
                return False
            magic = default_file_system.read_bytes(self.filepath, size=2)
            if magic == b"MZ":
                logger.debug("Found MZ header - likely PE file")
                return True
        except Exception as e:
            logger.debug(f"Could not read file magic bytes: {e}")
        return False

    def _check_info_command(self) -> bool:
        """Check `i` command output for PE marker."""
        try:
            info_text = self.adapter.get_info_text() if self.adapter else ""
            if info_text and "pe" in info_text.lower():
                logger.debug("PE detected via 'i' command")
                return True
        except Exception as e:
            logger.debug(f"Error with 'i' command: {e}")
        return False

    def _check_bin_info(self) -> bool:
        """Check `ij` command output for PE markers."""
        try:
            info_cmd = cmdj_helper(self.adapter, self.r2, "ij", {})
            if not info_cmd or "bin" not in info_cmd:
                return False
            bin_info = info_cmd["bin"]
            if self._bin_info_has_pe(bin_info):
                return True
        except Exception as e:
            logger.debug(f"Error with 'ij' command: {e}")
        return False

    def _bin_info_has_pe(self, bin_info: dict[str, Any]) -> bool:
        """Check bin info format/class for PE."""
        bin_format = bin_info.get("format", "").lower()
        if "pe" in bin_format:
            logger.debug("PE detected via 'ij' format field")
            return True
        bin_class = bin_info.get("class", "").lower()
        if "pe" in bin_class:
            logger.debug("PE detected via 'ij' class field")
            return True
        return False

    def _extract_rich_header(self) -> dict[str, Any] | None:
        """
        Extract Rich Header from PE file using direct file analysis.

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            logger.debug("Trying direct file analysis for Rich Header")
            rich_data = self._direct_file_rich_search()
            if rich_data:
                logger.debug("Successfully found Rich Header via direct file analysis")
                return rich_data

            logger.debug("Direct analysis failed, trying r2pipe search")
            rich_results, dans_results = self._collect_rich_dans_offsets()
            if not rich_results or not dans_results:
                logger.debug("r2pipe patterns not found, trying manual search in DOS stub area")
                return self._manual_rich_search()

            rich_data = self._try_rich_dans_combinations(rich_results, dans_results)
            if rich_data:
                return rich_data

            logger.debug("No valid Rich Header found with any strategy")
            return None

        except Exception as e:
            logger.error(f"Error extracting Rich Header: {e}")
            return None

    def _collect_rich_dans_offsets(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Scan for Rich/DanS patterns using r2pipe."""
        rich_results = self._scan_patterns(RICH_PATTERNS, "Rich")
        dans_results = self._scan_patterns(DANS_PATTERNS, "DanS")
        return rich_results, dans_results

    def _scan_patterns(self, patterns: list[str], label: str) -> list[dict[str, Any]]:
        """Scan for patterns and return combined results."""
        results: list[dict[str, Any]] = []
        for pattern in patterns:
            try:
                found = cmdj_helper(self.adapter, self.r2, f"/xj {pattern}", {})
                if found:
                    results.extend(found)
                    logger.debug(f"Found {label} pattern {pattern} at {len(found)} locations")
            except Exception as exc:
                logger.debug(f"Failed {label} pattern scan {pattern}: {exc}")
                continue
        return results

    def _try_rich_dans_combinations(
        self, rich_results: list[dict[str, Any]], dans_results: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Try combinations of Rich and DanS offsets."""
        for rich_result in rich_results:
            for dans_result in dans_results:
                offsets = self._extract_offsets(rich_result, dans_result)
                if not offsets:
                    continue
                dans_offset, rich_offset = offsets
                if not self._offsets_valid(dans_offset, rich_offset):
                    continue
                rich_data = self._try_extract_rich_at_offsets(dans_offset, rich_offset)
                if rich_data:
                    logger.debug(
                        f"Successfully extracted Rich Header at DanS:{dans_offset}, Rich:{rich_offset}"
                    )
                    return rich_data
        return None

    def _extract_offsets(
        self, rich_result: dict[str, Any], dans_result: dict[str, Any]
    ) -> tuple[int, int] | None:
        """Extract Rich/DanS offsets from result dicts."""
        rich_offset = rich_result.get("offset")
        dans_offset = dans_result.get("offset")
        if rich_offset is None or dans_offset is None:
            return None
        return dans_offset, rich_offset

    def _offsets_valid(self, dans_offset: int, rich_offset: int) -> bool:
        """Validate Rich/DanS relative offsets."""
        return dans_offset < rich_offset and (rich_offset - dans_offset) <= 1024

    def _direct_file_rich_search(self) -> dict[str, Any] | None:
        """
        Direct file analysis for Rich Header (most reliable method).

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            data = self._read_file_bytes()
            if not data or not self._is_valid_pe_data(data):
                return None

            pe_offset = self._get_pe_offset(data)
            if pe_offset is None:
                return None

            dos_stub = self._get_dos_stub(data, pe_offset)
            if dos_stub is None:
                return None

            rich_pos = self._find_rich_pos(dos_stub)
            if rich_pos is None:
                return None

            xor_key = self._extract_xor_key_from_stub(dos_stub, rich_pos)
            if xor_key is None:
                return None

            dans_pos = self._find_or_estimate_dans(dos_stub, rich_pos)
            if dans_pos is None:
                return None

            encoded_data = self._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
            if not encoded_data:
                return None

            entries = decode_rich_header(encoded_data, xor_key)
            if not entries:
                logger.debug("No valid entries decoded from Rich Header")
                return None

            calculated_checksum = self._calculate_rich_checksum(data, pe_offset, entries)
            return self._build_direct_rich_result(
                xor_key,
                calculated_checksum,
                entries,
                encoded_data,
                dos_stub_start=0x40,
                dans_pos=dans_pos,
                rich_pos=rich_pos,
            )

        except Exception as e:
            logger.error(f"Error in direct file Rich Header search: {e}")
            return None

    def _read_file_bytes(self) -> bytes | None:
        """Read the full file into memory."""
        try:
            if not self.filepath:
                return None
            return default_file_system.read_bytes(self.filepath)
        except Exception as e:
            logger.debug(f"Could not read file bytes: {e}")
            return None

    def _is_valid_pe_data(self, data: bytes) -> bool:
        """Validate minimal PE data structure."""
        return len(data) >= 0x40 and data[:2] == b"MZ"

    def _get_pe_offset(self, data: bytes) -> int | None:
        """Get PE header offset from DOS header."""
        pe_offset = int(struct.unpack("<I", data[0x3C : 0x3C + 4])[0])
        if pe_offset >= len(data) - 4:
            return None
        return int(pe_offset)

    def _get_dos_stub(self, data: bytes, pe_offset: int) -> bytes | None:
        """Extract DOS stub data."""
        dos_stub_start = 0x40
        if pe_offset <= dos_stub_start:
            return None
        return data[dos_stub_start:pe_offset]

    def _find_rich_pos(self, dos_stub: bytes) -> int | None:
        """Locate Rich signature within DOS stub."""
        rich_pos = dos_stub.find(b"Rich")
        if rich_pos == -1:
            logger.debug("Rich signature not found in DOS stub")
            return None
        logger.debug(f"Found Rich signature at DOS stub offset 0x{rich_pos:x}")
        return rich_pos

    def _extract_xor_key_from_stub(self, dos_stub: bytes, rich_pos: int) -> int | None:
        """Extract XOR key from Rich header position."""
        if rich_pos + 8 > len(dos_stub):
            logger.debug("Not enough data after Rich signature for XOR key")
            return None
        xor_key_bytes = dos_stub[rich_pos + 4 : rich_pos + 8]
        xor_key = int(struct.unpack("<I", xor_key_bytes)[0])
        logger.debug(f"Extracted XOR key: 0x{xor_key:08x}")
        return xor_key

    def _find_or_estimate_dans(self, dos_stub: bytes, rich_pos: int) -> int | None:
        """Find DanS signature or estimate encoded data start."""
        dans_pos = dos_stub[:rich_pos].rfind(b"DanS")
        if dans_pos != -1:
            logger.debug(f"Found DanS signature at DOS stub offset 0x{dans_pos:x}")
            return dans_pos
        logger.debug("DanS signature not found, trying to find encoded data start")
        return self._estimate_dans_start(dos_stub, rich_pos)

    def _estimate_dans_start(self, dos_stub: bytes, rich_pos: int) -> int | None:
        """Estimate start of Rich Header if DanS is missing."""
        for start_pos in range(max(0, rich_pos - 512), rich_pos, 4):
            if start_pos + 8 > len(dos_stub):
                continue
            test_data = dos_stub[start_pos:rich_pos]
            if len(test_data) >= 8 and len(test_data) % 8 == 0:
                logger.debug(f"Estimated Rich Header start at 0x{0x40 + start_pos:x}")
                return start_pos
        logger.debug("Could not determine Rich Header start")
        return None

    def _extract_encoded_from_stub(
        self, dos_stub: bytes, dans_pos: int, rich_pos: int
    ) -> bytes | None:
        """Extract encoded data between DanS/start and Rich."""
        encoded_data = dos_stub[dans_pos + 4 : rich_pos]
        if len(encoded_data) == 0 or len(encoded_data) % 8 != 0:
            logger.debug(f"Invalid encoded data length: {len(encoded_data)}")
            return None
        logger.debug(f"Extracted {len(encoded_data)} bytes of encoded data")
        return encoded_data

    def _build_direct_rich_result(
        self,
        xor_key: int,
        calculated_checksum: int,
        entries: list[dict[str, Any]],
        encoded_data: bytes,
        dos_stub_start: int,
        dans_pos: int,
        rich_pos: int,
    ) -> dict[str, Any]:
        """Build Rich Header result from direct file search."""
        rich_absolute_pos = dos_stub_start + rich_pos
        return {
            "xor_key": xor_key,
            "checksum": calculated_checksum,
            "entries": entries,
            "dans_offset": dos_stub_start + dans_pos,
            "rich_offset": rich_absolute_pos,
            "encoded_data": encoded_data.hex(),
            "valid_checksum": calculated_checksum == xor_key,
        }

    def _calculate_rich_checksum(
        self, data: bytes, pe_offset: int, entries: list[dict[str, Any]]
    ) -> int:
        """
        Calculate Rich Header checksum.

        Args:
            data: Full file data
            pe_offset: PE header offset
            entries: Decoded Rich Header entries

        Returns:
            Calculated checksum
        """
        try:
            checksum = pe_offset

            # Add DOS header bytes (skip e_lfanew field at 0x3C)
            for i in range(0x3C):
                checksum += data[i]
                checksum = checksum & 0xFFFFFFFF

            # Add each entry's contribution
            for entry in entries:
                prod_id = entry.get("product_id", 0)
                build_num = entry.get("build_number", 0)
                count = entry.get("count", 0)

                # Each entry contributes (prod_id | (build_num << 16)) * count
                entry_value = (prod_id | (build_num << 16)) * count
                checksum += entry_value
                checksum = checksum & 0xFFFFFFFF

            return checksum

        except Exception as e:
            logger.debug(f"Error calculating Rich Header checksum: {e}")
            return 0

    @staticmethod
    def is_available() -> bool:
        """
        Check if Rich Header analysis is available.
        Always returns True as it only depends on r2pipe.

        Returns:
            True if Rich Header analysis is available
        """
        return True

    @staticmethod
    def calculate_richpe_hash_from_file(filepath: str) -> str | None:
        """Calculate RichPE hash directly from a file path."""
        results = run_analyzer_on_file(RichHeaderAnalyzer, filepath)
        if results is None:
            logger.error("Error calculating RichPE hash from file")
            return None
        return cast(str | None, results.get("richpe_hash"))
