#!/usr/bin/env python3
"""
Rich Header Analyzer Module

This module extracts and analyzes the Rich Header from PE files.
The Rich Header is an undocumented Microsoft structure that contains
metadata about the build environment (compilers, linkers, tools used).

Based on research from:
- https://github.com/RichHeaderResearch/RichPE
- https://www.ntcore.com/files/richsign.htm
- https://bytepointer.com/articles/the_microsoft_rich_header.htm
- https://forensicitguy.github.io/rich-header-hashes-with-pefile/
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = get_logger(__name__)

# Try to import pefile for better Rich Header support
try:
    import pefile

    PEFILE_AVAILABLE = True
    logger.debug("pefile library available for Rich Header analysis")
except ImportError:
    PEFILE_AVAILABLE = False
    logger.debug("pefile library not available, using r2pipe fallback")


class RichHeaderAnalyzer:
    """Rich Header extraction and analysis for PE files"""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Rich Header analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the PE file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath

        # Known compiler product IDs (partial list)
        self.compiler_products = {
            0x0000: "Unknown",
            0x0001: "Import0",
            0x0002: "Linker510",
            0x0003: "Cvtomf510",
            0x0004: "Linker600",
            0x0005: "Cvtomf600",
            0x0006: "Cvtres500",
            0x0007: "Utc11_Basic",
            0x0008: "Utc11_C",
            0x0009: "Utc11_CPP",
            0x000A: "AliasObj60",
            0x000B: "VisualBasic60",
            0x000C: "Masm613",
            0x000D: "Masm710",
            0x000E: "Linker511",
            0x000F: "Cvtomf511",
            0x0010: "Masm614",
            0x0011: "Linker512",
            0x0012: "Cvtomf512",
            0x0013: "Utc12_Basic",
            0x0014: "Utc12_C",
            0x0015: "Utc12_CPP",
            0x0016: "AliasObj70",
            0x0017: "Linker620",
            0x0018: "Cvtomf620",
            0x0019: "AliasObj71",
            0x001A: "Linker621",
            0x001B: "Cvtomf621",
            0x001C: "Masm615",
            0x001D: "Utc13_Basic",
            0x001E: "Utc13_C",
            0x001F: "Utc13_CPP",
            0x0020: "AliasObj80",
            0x0021: "AliasObj90",
            0x0022: "Utc12_C_Std",
            0x0023: "Utc12_CPP_Std",
            0x0024: "Utc12_C_Book",
            0x0025: "Utc12_CPP_Book",
            0x0026: "Implib622",
            0x0027: "Cvtomf622",
            0x0028: "Cvtres501",
            0x002A: "Utc13_C_Std",
            0x002B: "Utc13_CPP_Std",
            0x002C: "Cvtpgd1300",
            0x002D: "Linker622",
            0x002E: "Linker700",
            0x002F: "Export622",
            0x0030: "Export700",
            0x0031: "Masm700",
            0x0032: "Utc13_POGO_I_C",
            0x0033: "Utc13_POGO_I_CPP",
            0x0034: "Utc13_POGO_O_C",
            0x0035: "Utc13_POGO_O_CPP",
            0x0036: "Cvtres700",
            0x0037: "Cvtres710p",
            0x0038: "Linker710p",
            0x0039: "Cvtomf710p",
            0x003A: "Export710p",
            0x003B: "Implib710p",
            0x003C: "Masm710p",
            0x003D: "Utc1310p_C",
            0x003E: "Utc1310p_CPP",
            0x003F: "Utc1310p_C_Std",
            0x0040: "Utc1310p_CPP_Std",
            0x0041: "Utc1310p_LTCG_C",
            0x0042: "Utc1310p_LTCG_CPP",
            0x0043: "Utc1310p_POGO_I_C",
            0x0044: "Utc1310p_POGO_I_CPP",
            0x0045: "Utc1310p_POGO_O_C",
            0x0046: "Utc1310p_POGO_O_CPP",
            0x0047: "Linker624",
            0x0048: "Cvtomf624",
            0x0049: "Export624",
            0x004A: "Implib624",
            0x004B: "Linker710",
            0x004C: "Cvtomf710",
            0x004D: "Export710",
            0x004E: "Implib710",
            0x004F: "Cvtres710",
            0x0050: "Utc1310_C",
            0x0051: "Utc1310_CPP",
            0x0052: "Utc1310_C_Std",
            0x0053: "Utc1310_CPP_Std",
            0x0054: "Utc1310_LTCG_C",
            0x0055: "Utc1310_LTCG_CPP",
            0x0056: "Utc1310_POGO_I_C",
            0x0057: "Utc1310_POGO_I_CPP",
            0x0058: "Utc1310_POGO_O_C",
            0x0059: "Utc1310_POGO_O_CPP",
            0x005A: "Cvtpgd1310",
            0x005B: "Linker771",
            0x005C: "Cvtomf771",
            0x005D: "Export771",
            0x005E: "Implib771",
            0x005F: "Cvtres771",
            0x0060: "Utc1400_C",
            0x0061: "Utc1400_CPP",
            0x0062: "Utc1400_C_Std",
            0x0063: "Utc1400_CPP_Std",
            0x0064: "Utc1400_LTCG_C",
            0x0065: "Utc1400_LTCG_CPP",
            0x0066: "Utc1400_POGO_I_C",
            0x0067: "Utc1400_POGO_I_CPP",
            0x0068: "Utc1400_POGO_O_C",
            0x0069: "Utc1400_POGO_O_CPP",
            0x006A: "Cvtpgd1400",
            0x006B: "Linker800",
            0x006C: "Cvtomf800",
            0x006D: "Export800",
            0x006E: "Implib800",
            0x006F: "Cvtres800",
            0x0070: "Masm800",
            0x0071: "Utc1500_C",
            0x0072: "Utc1500_CPP",
            0x0073: "Utc1500_C_Std",
            0x0074: "Utc1500_CPP_Std",
            0x0075: "Utc1500_LTCG_C",
            0x0076: "Utc1500_LTCG_CPP",
            0x0077: "Utc1500_POGO_I_C",
            0x0078: "Utc1500_POGO_I_CPP",
            0x0079: "Utc1500_POGO_O_C",
            0x007A: "Utc1500_POGO_O_CPP",
            0x007B: "Cvtpgd1500",
            0x007C: "Linker900",
            0x007D: "Cvtomf900",
            0x007E: "Export900",
            0x007F: "Implib900",
            0x0080: "Cvtres900",
            0x0081: "Masm900",
            0x0082: "Utc1600_C",
            0x0083: "Utc1600_CPP",
            0x0084: "Utc1600_C_Std",
            0x0085: "Utc1600_CPP_Std",
            0x0086: "Utc1600_LTCG_C",
            0x0087: "Utc1600_LTCG_CPP",
            0x0088: "Utc1600_POGO_I_C",
            0x0089: "Utc1600_POGO_I_CPP",
            0x008A: "Utc1600_POGO_O_C",
            0x008B: "Utc1600_POGO_O_CPP",
            0x008C: "Cvtpgd1600",
            0x008D: "Linker1000",
            0x008E: "Cvtomf1000",
            0x008F: "Export1000",
            0x0090: "Implib1000",
            0x0091: "Cvtres1000",
            0x0092: "Masm1000",
            0x0093: "Utc1700_C",
            0x0094: "Utc1700_CPP",
            0x0095: "Utc1700_C_Std",
            0x0096: "Utc1700_CPP_Std",
            0x0097: "Utc1700_LTCG_C",
            0x0098: "Utc1700_LTCG_CPP",
            0x0099: "Utc1700_POGO_I_C",
            0x009A: "Utc1700_POGO_I_CPP",
            0x009B: "Utc1700_POGO_O_C",
            0x009C: "Utc1700_POGO_O_CPP",
            0x009D: "Cvtpgd1700",
            0x009E: "Linker1100",
            0x009F: "Cvtomf1100",
            0x00A0: "Export1100",
            0x00A1: "Implib1100",
            0x00A2: "Cvtres1100",
            0x00A3: "Masm1100",
            0x00A4: "Utc1800_C",
            0x00A5: "Utc1800_CPP",
            0x00A6: "Utc1800_C_Std",
            0x00A7: "Utc1800_CPP_Std",
            0x00A8: "Utc1800_LTCG_C",
            0x00A9: "Utc1800_LTCG_CPP",
            0x00AA: "Utc1800_POGO_I_C",
            0x00AB: "Utc1800_POGO_I_CPP",
            0x00AC: "Utc1800_POGO_O_C",
            0x00AD: "Utc1800_POGO_O_CPP",
            0x00AE: "Cvtpgd1800",
            0x00AF: "Linker1200",
            0x00B0: "Cvtomf1200",
            0x00B1: "Export1200",
            0x00B2: "Implib1200",
            0x00B3: "Cvtres1200",
            0x00B4: "Masm1200",
            0x00B5: "Utc1900_C",
            0x00B6: "Utc1900_CPP",
            0x00B7: "Utc1900_C_Std",
            0x00B8: "Utc1900_CPP_Std",
            0x00B9: "Utc1900_LTCG_C",
            0x00BA: "Utc1900_LTCG_CPP",
            0x00BB: "Utc1900_POGO_I_C",
            0x00BC: "Utc1900_POGO_I_CPP",
            0x00BD: "Utc1900_POGO_O_C",
            0x00BE: "Utc1900_POGO_O_CPP",
            0x00BF: "Cvtpgd1900",
            0x00C0: "Linker1300",
            0x00C1: "Cvtomf1300",
            0x00C2: "Export1300",
            0x00C3: "Implib1300",
            0x00C4: "Cvtres1300",
            0x00C5: "Masm1300",
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Perform Rich Header analysis on PE file.

        Returns:
            Dictionary containing Rich Header analysis results
        """
        logger.debug(f"Starting Rich Header analysis for {self.filepath}")

        results = {
            "available": False,
            "rich_header": None,
            "compilers": [],
            "xor_key": None,
            "checksum": None,
            "richpe_hash": None,
            "error": None,
            "is_pe": False,
            "method_used": None,
        }

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
            compilers = self._parse_compiler_entries(rich_data.get("entries", []))
            results["compilers"] = compilers
            logger.debug(f"Parsed {len(compilers)} compiler entries")

            # Calculate RichPE hash
            richpe_hash = self._calculate_richpe_hash(rich_data)
            if richpe_hash:
                results["richpe_hash"] = richpe_hash
                logger.debug(f"Calculated RichPE hash: {richpe_hash}")

        except Exception as e:
            logger.error(f"Rich Header analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _extract_rich_header_pefile(self) -> Optional[Dict[str, Any]]:
        """
        Extract Rich Header using pefile library (most reliable method).

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        if not PEFILE_AVAILABLE:
            return None

        try:
            # Load PE file with pefile
            pe = pefile.PE(self.filepath)

            # Check if Rich Header is available
            if not hasattr(pe, "RICH_HEADER") or not pe.RICH_HEADER:
                logger.debug("No Rich Header found by pefile")
                return None

            # Get Rich Header hash using pefile's built-in method
            rich_hash = pe.get_rich_header_hash()
            if not rich_hash:
                logger.debug("Could not calculate Rich Header hash with pefile")
                return None

            logger.debug(f"pefile calculated Rich Header hash: {rich_hash}")

            # Extract Rich Header details
            xor_key = pe.RICH_HEADER.checksum if hasattr(pe.RICH_HEADER, "checksum") else None

            # Parse entries from Rich Header
            entries = []
            if hasattr(pe.RICH_HEADER, "values") and pe.RICH_HEADER.values:
                for entry in pe.RICH_HEADER.values:
                    if (
                        hasattr(entry, "product_id")
                        and hasattr(entry, "build_version")
                        and hasattr(entry, "count")
                    ):
                        # pefile uses different field names
                        entries.append(
                            {
                                "product_id": entry.product_id,
                                "build_number": entry.build_version,
                                "count": entry.count,
                                "prodid": (entry.product_id | (entry.build_version << 16)),
                            }
                        )

            # Alternative approach if direct access doesn't work
            if not entries and hasattr(pe.RICH_HEADER, "clear_data"):
                # Parse clear_data manually
                clear_data = pe.RICH_HEADER.clear_data
                entries = self._parse_clear_data_entries(clear_data)

            pe.close()

            return {
                "xor_key": xor_key,
                "checksum": xor_key,
                "entries": entries,
                "richpe_hash": rich_hash,
                "clear_data": (
                    pe.RICH_HEADER.clear_data.hex()
                    if hasattr(pe.RICH_HEADER, "clear_data")
                    else None
                ),
                "method": "pefile",
                "clear_data_bytes": (
                    pe.RICH_HEADER.clear_data if hasattr(pe.RICH_HEADER, "clear_data") else None
                ),
            }

        except Exception as e:
            logger.debug(f"pefile Rich Header extraction failed: {e}")
            return None

    def _parse_clear_data_entries(self, clear_data: bytes) -> List[Dict[str, Any]]:
        """
        Parse Rich Header entries from clear data.

        Args:
            clear_data: Clear (decoded) Rich Header data

        Returns:
            List of parsed entries
        """
        entries = []

        try:
            # Process in 8-byte chunks (4 bytes prodid + 4 bytes count)
            for i in range(0, len(clear_data), 8):
                if i + 8 > len(clear_data):
                    break

                prodid, count = struct.unpack("<II", clear_data[i : i + 8])

                if count > 0:  # Skip empty entries
                    # Extract product ID and build number
                    product_id = prodid & 0xFFFF
                    build_number = (prodid >> 16) & 0xFFFF

                    entries.append(
                        {
                            "product_id": product_id,
                            "build_number": build_number,
                            "count": count,
                            "prodid": prodid,
                        }
                    )

        except Exception as e:
            logger.debug(f"Error parsing clear data entries: {e}")

        return entries

    def _extract_rich_header_r2pipe(self) -> Optional[Dict[str, Any]]:
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
            # First check if r2 instance is valid
            if not self.r2:
                logger.error("r2 instance is None")
                return False

            # Check file magic bytes directly first (most reliable)
            try:
                with open(self.filepath, "rb") as f:
                    magic = f.read(2)
                    # PE files start with MZ
                    if magic == b"MZ":
                        logger.debug("Found MZ header - likely PE file")
                        return True
            except Exception as e:
                logger.debug(f"Could not read file magic bytes: {e}")

            # Check file info command
            try:
                info_text = self.r2.cmd("i")
                if info_text and "pe" in info_text.lower():
                    logger.debug("PE detected via 'i' command")
                    return True
            except Exception as e:
                logger.debug(f"Error with 'i' command: {e}")

            # Check binary info via ij command
            try:
                info_cmd = safe_cmdj(self.r2, "ij", {})
                if info_cmd and "bin" in info_cmd:
                    bin_info = info_cmd["bin"]

                    # Check format field
                    bin_format = bin_info.get("format", "").lower()
                    if "pe" in bin_format:
                        logger.debug("PE detected via 'ij' format field")
                        return True

                    # Check class field
                    bin_class = bin_info.get("class", "").lower()
                    if "pe" in bin_class:
                        logger.debug("PE detected via 'ij' class field")
                        return True
            except Exception as e:
                logger.debug(f"Error with 'ij' command: {e}")

            return False

        except Exception as e:
            logger.error(f"Error checking if file is PE: {e}")
            return False

    def _extract_rich_header(self) -> Optional[Dict[str, Any]]:
        """
        Extract Rich Header from PE file using direct file analysis.

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            # Strategy 1: Direct file analysis (most reliable)
            logger.debug("Trying direct file analysis for Rich Header")
            rich_data = self._direct_file_rich_search()
            if rich_data:
                logger.debug("Successfully found Rich Header via direct file analysis")
                return rich_data

            # Strategy 2: r2pipe search (fallback)
            logger.debug("Direct analysis failed, trying r2pipe search")

            # Search for Rich signature in different byte orders
            rich_patterns = [
                "52696368",  # "Rich" in little-endian
                "68636952",  # "Rich" in big-endian
                "5269636800000000",  # "Rich" + null padding
            ]

            dans_patterns = [
                "44616e53",  # "DanS" in little-endian
                "536e6144",  # "DanS" in big-endian
                "44616e5300000000",  # "DanS" + null padding
            ]

            rich_results = []
            dans_results = []

            # Try each pattern
            for pattern in rich_patterns:
                try:
                    results = safe_cmd_list(self.r2, f"/xj {pattern}")
                    if results:
                        rich_results.extend(results)
                        logger.debug(f"Found Rich pattern {pattern} at {len(results)} locations")
                except Exception:
                    continue

            for pattern in dans_patterns:
                try:
                    results = safe_cmd_list(self.r2, f"/xj {pattern}")
                    if results:
                        dans_results.extend(results)
                        logger.debug(f"Found DanS pattern {pattern} at {len(results)} locations")
                except Exception:
                    continue

            # Strategy 3: If no patterns found, try manual search in DOS stub area
            if not rich_results or not dans_results:
                logger.debug("r2pipe patterns not found, trying manual search in DOS stub area")
                return self._manual_rich_search()

            # Strategy 4: Try all combinations of Rich and DanS offsets
            for rich_result in rich_results:
                for dans_result in dans_results:
                    rich_offset = rich_result.get("offset")
                    dans_offset = dans_result.get("offset")

                    if rich_offset is None or dans_offset is None:
                        continue

                    # Validate that DanS comes before Rich (with some tolerance)
                    if dans_offset >= rich_offset or (rich_offset - dans_offset) > 1024:
                        continue

                    # Try to extract and validate this Rich Header
                    rich_data = self._try_extract_rich_at_offsets(dans_offset, rich_offset)
                    if rich_data:
                        logger.debug(
                            f"Successfully extracted Rich Header at DanS:{dans_offset}, Rich:{rich_offset}"
                        )
                        return rich_data

            logger.debug("No valid Rich Header found with any strategy")
            return None

        except Exception as e:
            logger.error(f"Error extracting Rich Header: {e}")
            return None

    def _direct_file_rich_search(self) -> Optional[Dict[str, Any]]:
        """
        Direct file analysis for Rich Header (most reliable method).

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            # Read the file directly
            with open(self.filepath, "rb") as f:
                data = f.read()

            # Validate PE structure
            if len(data) < 0x40 or data[:2] != b"MZ":
                return None

            # Get PE header offset
            pe_offset = struct.unpack("<I", data[0x3C : 0x3C + 4])[0]
            if pe_offset >= len(data) - 4:
                return None

            # Analyze DOS stub area
            dos_stub_start = 0x40
            dos_stub_end = pe_offset

            if dos_stub_end <= dos_stub_start:
                return None

            dos_stub = data[dos_stub_start:dos_stub_end]

            # Look for Rich signature
            rich_pos = dos_stub.find(b"Rich")
            if rich_pos == -1:
                logger.debug("Rich signature not found in DOS stub")
                return None

            rich_absolute_pos = dos_stub_start + rich_pos
            logger.debug(f"Found Rich signature at absolute position 0x{rich_absolute_pos:x}")

            # Extract XOR key (4 bytes after Rich)
            if rich_pos + 8 > len(dos_stub):
                logger.debug("Not enough data after Rich signature for XOR key")
                return None

            xor_key_bytes = dos_stub[rich_pos + 4 : rich_pos + 8]
            xor_key = struct.unpack("<I", xor_key_bytes)[0]
            logger.debug(f"Extracted XOR key: 0x{xor_key:08x}")

            # Find DanS signature by working backwards from Rich
            # DanS should be at the beginning of the Rich Header
            dans_search_area = dos_stub[:rich_pos]
            dans_pos = dans_search_area.rfind(b"DanS")

            if dans_pos == -1:
                # Sometimes DanS is not present or encoded differently
                # Try to find the start of encoded data by looking for patterns
                logger.debug("DanS signature not found, trying to find encoded data start")

                # Look for the start of the Rich Header by finding repeated XOR patterns
                # Rich Headers typically start with encoded entries
                for start_pos in range(max(0, rich_pos - 512), rich_pos, 4):
                    if start_pos + 8 <= len(dos_stub):
                        # Try this as potential start
                        test_data = dos_stub[start_pos:rich_pos]
                        if len(test_data) >= 8 and len(test_data) % 8 == 0:
                            # This could be our encoded data
                            dans_pos = start_pos
                            logger.debug(
                                f"Estimated Rich Header start at 0x{dos_stub_start + dans_pos:x}"
                            )
                            break

                if dans_pos == -1:
                    logger.debug("Could not determine Rich Header start")
                    return None
            else:
                logger.debug(f"Found DanS signature at DOS stub offset 0x{dans_pos:x}")

            # Extract encoded data between DanS/start and Rich
            encoded_data = dos_stub[dans_pos + 4 : rich_pos]  # +4 to skip DanS signature

            if len(encoded_data) == 0 or len(encoded_data) % 8 != 0:
                logger.debug(f"Invalid encoded data length: {len(encoded_data)}")
                return None

            logger.debug(f"Extracted {len(encoded_data)} bytes of encoded data")

            # Decode the Rich Header entries
            entries = self._decode_rich_header(encoded_data, xor_key)

            if not entries:
                logger.debug("No valid entries decoded from Rich Header")
                return None

            logger.debug(f"Successfully decoded {len(entries)} Rich Header entries")

            # Calculate checksum (should match XOR key)
            calculated_checksum = self._calculate_rich_checksum(data, pe_offset, entries)

            return {
                "xor_key": xor_key,
                "checksum": calculated_checksum,
                "entries": entries,
                "dans_offset": dos_stub_start + dans_pos,
                "rich_offset": rich_absolute_pos,
                "encoded_data": encoded_data.hex(),
                "valid_checksum": calculated_checksum == xor_key,
            }

        except Exception as e:
            logger.error(f"Error in direct file Rich Header search: {e}")
            return None

    def _calculate_rich_checksum(
        self, data: bytes, pe_offset: int, entries: List[Dict[str, Any]]
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

    def _manual_rich_search(self) -> Optional[Dict[str, Any]]:
        """
        Manual search for Rich Header in DOS stub area when patterns fail.

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            # Read more data to ensure we capture the Rich Header
            # PE files can have larger DOS stubs, so read up to 2KB
            self.r2.cmd("s 0")
            data_bytes = safe_cmd_list(self.r2, "p8j 2048")
            if not data_bytes:
                return None

            data = bytes(data_bytes)

            # Look for Rich and DanS signatures manually with different variations
            signatures_to_try = [
                (b"Rich", b"DanS"),
                (b"hciR", b"SnaD"),  # Reversed byte order
            ]

            for rich_sig, dans_sig in signatures_to_try:
                rich_offsets = []
                dans_offsets = []

                # Find all occurrences of this signature pair
                start = 0
                while True:
                    pos = data.find(rich_sig, start)
                    if pos == -1:
                        break
                    rich_offsets.append(pos)
                    start = pos + 1

                start = 0
                while True:
                    pos = data.find(dans_sig, start)
                    if pos == -1:
                        break
                    dans_offsets.append(pos)
                    start = pos + 1

                logger.debug(
                    f"Manual search found Rich at: {rich_offsets}, DanS at: {dans_offsets}"
                )

                # Try combinations for this signature pair
                for dans_offset in dans_offsets:
                    for rich_offset in rich_offsets:
                        if dans_offset < rich_offset and (rich_offset - dans_offset) <= 512:
                            rich_data = self._try_extract_rich_at_offsets(dans_offset, rich_offset)
                            if rich_data:
                                logger.debug(
                                    f"Found valid Rich Header with signature pair {rich_sig}/{dans_sig}"
                                )
                                return rich_data

            # Additional strategy: Look for characteristic Rich Header patterns
            # Rich Headers often have repeating null bytes and specific structures
            return self._pattern_based_rich_search(data)

        except Exception as e:
            logger.error(f"Error in manual Rich Header search: {e}")
            return None

    def _pattern_based_rich_search(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Pattern-based search for Rich Header using structural characteristics.

        Args:
            data: Raw file data to search

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            # Look for potential XOR keys (4 bytes after "Rich")
            # Rich Headers typically have the pattern: DanS...Rich[4-byte-key]

            for i in range(len(data) - 8):
                # Look for potential Rich signature area
                if data[i : i + 4] == b"Rich":
                    # Extract potential XOR key
                    if i + 8 <= len(data):
                        potential_key = struct.unpack("<I", data[i + 4 : i + 8])[0]

                        # Skip if key is 0 or looks invalid
                        if potential_key == 0 or potential_key == 0xFFFFFFFF:
                            continue

                        # Look backwards for DanS signature
                        for j in range(max(0, i - 512), i):
                            if data[j : j + 4] == b"DanS":
                                # Try to extract Rich Header at these offsets
                                rich_data = self._try_extract_rich_at_offsets(j, i)
                                if rich_data:
                                    logger.debug(
                                        f"Pattern-based search found Rich Header at DanS:{j}, Rich:{i}"
                                    )
                                    return rich_data

            return None

        except Exception as e:
            logger.debug(f"Error in pattern-based Rich Header search: {e}")
            return None

    def _try_extract_rich_at_offsets(
        self, dans_offset: int, rich_offset: int
    ) -> Optional[Dict[str, Any]]:
        """
        Try to extract Rich Header at specific offsets.

        Args:
            dans_offset: Offset of DanS signature
            rich_offset: Offset of Rich signature

        Returns:
            Dictionary containing Rich Header data or None if extraction fails
        """
        try:
            rich_size = rich_offset - dans_offset
            if not self._validate_rich_size(rich_size):
                return None

            xor_key = self._extract_xor_key(rich_offset)
            if xor_key is None:
                return None

            encoded_data = self._extract_encoded_data(dans_offset, rich_size)
            if encoded_data is None:
                return None

            decoded_entries = self._decode_rich_header(encoded_data, xor_key)
            if not self._validate_decoded_entries(decoded_entries):
                return None

            return self._build_rich_header_result(decoded_entries, xor_key)

        except Exception as e:
            logger.debug(f"Error extracting Rich Header: {e}")
            return None

    def _validate_rich_size(self, rich_size: int) -> bool:
        """Validate Rich Header size"""
        return rich_size > 8 and rich_size <= 512

    def _extract_xor_key(self, rich_offset: int) -> Optional[int]:
        """Extract and validate XOR key"""
        xor_key_offset = rich_offset + 4
        self.r2.cmd(f"s {xor_key_offset}")
        xor_key_bytes = safe_cmd_list(self.r2, "p8j 4")

        if not xor_key_bytes or len(xor_key_bytes) < 4:
            return None

        xor_key = struct.unpack("<I", bytes(xor_key_bytes))[0]
        return xor_key if xor_key != 0 else None

    def _extract_encoded_data(self, dans_offset: int, rich_size: int) -> Optional[bytes]:
        """Extract encoded Rich Header data"""
        self.r2.cmd(f"s {dans_offset}")
        encoded_data = safe_cmd_list(self.r2, f"p8j {rich_size}")

        if not encoded_data or len(encoded_data) < 8:
            return None

        return bytes(encoded_data)

    def _validate_decoded_entries(self, decoded_entries: List[Dict]) -> bool:
        """Validate decoded Rich Header entries"""
        if not decoded_entries:
            return False

        valid_entries = 0
        for entry in decoded_entries:
            prodid = entry.get("prodid", 0)
            count = entry.get("count", 0)
            if 0 < count < 10000 and 0 <= prodid < 0x10000:
                valid_entries += 1

        return valid_entries > 0

    def _build_rich_header_result(
        self, decoded_entries: List[Dict], xor_key: int
    ) -> Dict[str, Any]:
        """Build the final Rich Header result dictionary"""
        # Calculate checksum (XOR of all decoded entries)
        checksum = 0
        for entry in decoded_entries:
            checksum ^= entry.get("prodid", 0)
            checksum ^= entry.get("count", 0)

        logger.debug(
            f"Extracted Rich Header with {len(decoded_entries)} entries, XOR key: 0x{xor_key:08x}"
        )

        return {
            "xor_key": xor_key,
            "checksum": checksum,
            "entries": decoded_entries,
        }

    def _decode_rich_header(self, encoded_data: bytes, xor_key: int) -> List[Dict[str, Any]]:
        """
        Decode Rich Header entries by XORing with the key.

        Args:
            encoded_data: Raw encoded Rich Header bytes
            xor_key: XOR key for decoding

        Returns:
            List of decoded Rich Header entries
        """
        entries = []

        try:
            # Skip the DanS signature (first 4 bytes) and process in 8-byte chunks
            # Each entry is 8 bytes: 4 bytes prodid + 4 bytes count
            for i in range(4, len(encoded_data) - 4, 8):  # -4 to skip Rich signature at end
                if i + 8 > len(encoded_data):
                    break

                # Extract 8 bytes for this entry
                entry_bytes = encoded_data[i : i + 8]
                if len(entry_bytes) < 8:
                    break

                # Decode as two 32-bit little-endian integers
                prodid_encoded, count_encoded = struct.unpack("<II", entry_bytes)

                # XOR decode
                prodid = prodid_encoded ^ xor_key
                count = count_encoded ^ xor_key

                # Skip entries with zero count (padding)
                if count > 0:
                    entries.append(
                        {
                            "prodid": prodid,
                            "count": count,
                            "prodid_encoded": prodid_encoded,
                            "count_encoded": count_encoded,
                        }
                    )

        except Exception as e:
            logger.error(f"Error decoding Rich Header: {e}")

        return entries

    def _parse_compiler_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Rich Header entries into human-readable compiler information.

        Args:
            entries: List of decoded Rich Header entries

        Returns:
            List of compiler information dictionaries
        """
        compilers = []

        for entry in entries:
            prodid = entry.get("prodid", 0)
            count = entry.get("count", 0)

            # Extract product ID and build number
            # Product ID is in the lower 16 bits, build number in upper 16 bits
            product_id = prodid & 0xFFFF
            build_number = (prodid >> 16) & 0xFFFF

            # Look up compiler name
            compiler_name = self.compiler_products.get(product_id, f"Unknown_0x{product_id:04X}")

            compilers.append(
                {
                    "product_id": product_id,
                    "build_number": build_number,
                    "count": count,
                    "compiler_name": compiler_name,
                    "full_prodid": prodid,
                    "description": self._get_compiler_description(compiler_name, build_number),
                }
            )

        return compilers

    def _get_compiler_description(self, compiler_name: str, build_number: int) -> str:
        """
        Get human-readable description for compiler.

        Args:
            compiler_name: Name of the compiler
            build_number: Build number

        Returns:
            Human-readable description
        """
        descriptions = {
            "Utc": "Microsoft C/C++ Compiler",
            "Linker": "Microsoft Linker",
            "Masm": "Microsoft Macro Assembler",
            "Cvtres": "Microsoft Resource Converter",
            "Export": "Microsoft Export Tool",
            "Implib": "Microsoft Import Library Tool",
            "Cvtomf": "Microsoft OMF Converter",
            "AliasObj": "Microsoft Alias Object Tool",
            "VisualBasic": "Microsoft Visual Basic",
            "Cvtpgd": "Microsoft Profile Guided Optimization Tool",
        }

        for key, desc in descriptions.items():
            if key in compiler_name:
                return f"{desc} (Build {build_number})"

        return f"{compiler_name} (Build {build_number})"

    def _calculate_richpe_hash(self, rich_data: Dict[str, Any]) -> Optional[str]:
        """
        Calculate RichPE hash based on VirusTotal standard (MD5 of clear bytes).

        This follows the standard used by VirusTotal and pefile library:
        - Use the clear_data_bytes directly from pefile if available
        - Otherwise, build clear bytes from decoded entries
        - Calculate MD5 hash of the clear bytes (not encoded entries)

        Args:
            rich_data: Rich Header data dictionary

        Returns:
            RichPE hash string or None if calculation fails
        """
        try:
            # If we have clear_data_bytes from pefile, use them directly (most accurate)
            if "clear_data_bytes" in rich_data and rich_data["clear_data_bytes"]:
                clear_bytes = rich_data["clear_data_bytes"]
                richpe_hash = hashlib.md5(clear_bytes, usedforsecurity=False).hexdigest()
                logger.debug(
                    f"RichPE hash calculated from pefile clear_data_bytes ({len(clear_bytes)} bytes)"
                )
                return richpe_hash

            # If we already have the hash from pefile, use it directly
            if "richpe_hash" in rich_data and rich_data["richpe_hash"]:
                logger.debug("Using RichPE hash directly from pefile")
                return rich_data["richpe_hash"]

            # Fallback: build clear bytes from decoded entries (less accurate)
            entries = rich_data.get("entries", [])
            if not entries:
                return None

            # Build clear bytes from decoded entries
            # Each entry is 8 bytes: 4 bytes prodid + 4 bytes count (little-endian)
            clear_bytes = bytearray()

            for entry in entries:
                prodid = entry.get("prodid", 0)
                count = entry.get("count", 0)

                # Pack as little-endian 32-bit integers
                clear_bytes.extend(struct.pack("<I", prodid))
                clear_bytes.extend(struct.pack("<I", count))

            # Calculate MD5 hash of clear bytes (this matches VirusTotal standard)
            richpe_hash = hashlib.md5(clear_bytes, usedforsecurity=False).hexdigest()

            logger.debug(
                f"RichPE hash calculated from reconstructed entries ({len(clear_bytes)} clear bytes)"
            )
            return richpe_hash

        except Exception as e:
            logger.error(f"Error calculating RichPE hash: {e}")
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if Rich Header analysis is available.
        Always returns True as it only depends on r2pipe.

        Returns:
            True if Rich Header analysis is available
        """
        return True

    def _debug_file_structure(self):
        """
        Debug method to analyze file structure when Rich Header is not found.
        """
        try:
            logger.debug("=== DEBUGGING FILE STRUCTURE ===")

            # Get file size
            self.r2.cmd("s 0")
            file_size = safe_cmdj(self.r2, "ij", {}).get("core", {}).get("size", 0)
            logger.debug(f"File size: {file_size} bytes")

            # Read first 512 bytes and look for patterns
            data_bytes = safe_cmd_list(self.r2, "p8j 512")
            if data_bytes:
                data = bytes(data_bytes)

                # Look for MZ header
                if data[:2] == b"MZ":
                    logger.debug("Found MZ header at offset 0")

                    # Look for PE header offset
                    if len(data) >= 0x3C + 4:
                        pe_offset = struct.unpack("<I", data[0x3C : 0x3C + 4])[0]
                        logger.debug(f"PE header offset: 0x{pe_offset:x}")

                        # Check what's between MZ and PE
                        if pe_offset > 64:  # Reasonable space for Rich Header
                            stub_data = data[64 : min(pe_offset, len(data))]
                            logger.debug(f"DOS stub size: {len(stub_data)} bytes")

                            # Look for any Rich/DanS patterns in stub
                            rich_pos = stub_data.find(b"Rich")
                            dans_pos = stub_data.find(b"DanS")

                            if rich_pos != -1:
                                logger.debug(f"Found 'Rich' at DOS stub offset: {rich_pos + 64}")
                            if dans_pos != -1:
                                logger.debug(f"Found 'DanS' at DOS stub offset: {dans_pos + 64}")

                            # Show hex dump of suspicious areas
                            if rich_pos != -1 or dans_pos != -1:
                                if dans_pos != -1 and rich_pos != -1:
                                    start = max(0, min(rich_pos, dans_pos) - 16)
                                elif rich_pos != -1:
                                    start = rich_pos - 16
                                else:
                                    start = dans_pos - 16
                                if dans_pos != -1 and rich_pos != -1:
                                    end = min(len(stub_data), max(rich_pos, dans_pos) + 32)
                                elif rich_pos != -1:
                                    end = rich_pos + 32
                                else:
                                    end = dans_pos + 32
                                hex_dump = stub_data[start:end].hex()
                                logger.debug(f"Hex dump around signatures: {hex_dump}")

                # Alternative: Search entire first 2KB for patterns
                logger.debug("Searching first 2KB for Rich Header patterns...")
                extended_data = safe_cmd_list(self.r2, "p8j 2048")
                if extended_data:
                    extended_bytes = bytes(extended_data)

                    # Find all occurrences
                    rich_positions = []
                    dans_positions = []

                    pos = 0
                    while pos < len(extended_bytes) - 4:
                        if extended_bytes[pos : pos + 4] == b"Rich":
                            rich_positions.append(pos)
                        if extended_bytes[pos : pos + 4] == b"DanS":
                            dans_positions.append(pos)
                        pos += 1

                    logger.debug(f"Found 'Rich' at positions: {rich_positions}")
                    logger.debug(f"Found 'DanS' at positions: {dans_positions}")

                    # Try to extract at these positions manually
                    for dans_pos in dans_positions:
                        for rich_pos in rich_positions:
                            if dans_pos < rich_pos and (rich_pos - dans_pos) < 512:
                                logger.debug(
                                    f"Attempting manual extraction at DanS:{dans_pos}, Rich:{rich_pos}"
                                )
                                # Show the data between them
                                segment = extended_bytes[dans_pos : rich_pos + 8]
                                logger.debug(
                                    f"Rich Header candidate ({len(segment)} bytes): {segment.hex()}"
                                )

        except Exception as e:
            logger.debug(f"Debug analysis failed: {e}")

    @staticmethod
    def calculate_richpe_hash_from_file(filepath: str) -> Optional[str]:
        """
        Calculate RichPE hash directly from a file path.

        Args:
            filepath: Path to the PE file

        Returns:
            RichPE hash string or None if calculation fails
        """
        try:
            import r2pipe

            with r2pipe.open(filepath, flags=["-2"]) as r2:
                analyzer = RichHeaderAnalyzer(r2, filepath)
                results = analyzer.analyze()
                return results.get("richpe_hash")

        except Exception as e:
            logger.error(f"Error calculating RichPE hash from file: {e}")
            return None
