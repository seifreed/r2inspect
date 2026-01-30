#!/usr/bin/env python3
"""
Section Analysis Module using r2pipe
"""

import math
from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class SectionAnalyzer(BaseAnalyzer):
    """PE sections analysis using radare2"""

    def __init__(self, r2, config):
        super().__init__(r2=r2, config=config)

        # Standard PE section names
        self.standard_sections = [
            ".text",
            ".data",
            ".rdata",
            ".bss",
            ".idata",
            ".edata",
            ".rsrc",
            ".reloc",
            ".debug",
            ".pdata",
            ".xdata",
        ]

    def get_category(self) -> str:
        return "metadata"

    def get_description(self) -> str:
        return "Analyzes binary sections including entropy, permissions, and suspicious characteristics"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32", "PE32+", "ELF", "MACH0", "MACHO"}

    def analyze(self) -> dict[str, Any]:
        """Perform section analysis"""
        result = self._init_result_structure({"total_sections": 0, "sections": [], "summary": {}})

        try:
            self._log_info("Starting section analysis")
            sections = self.analyze_sections()
            summary = self.get_section_summary()

            result["sections"] = sections
            result["summary"] = summary
            result["total_sections"] = len(sections)
            result["available"] = True
            self._log_info(f"Analyzed {len(sections)} sections")
        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"Section analysis failed: {e}")

        return result

    def analyze_sections(self) -> list[dict[str, Any]]:
        """Analyze all sections in the PE file"""
        sections_info = []

        try:
            sections = safe_cmdj(self.r2, "iSj", [])

            if sections and isinstance(sections, list):
                for section in sections:
                    # Ensure section is a dict
                    if isinstance(section, dict):
                        section_analysis = self._analyze_single_section(section)
                        sections_info.append(section_analysis)
                    else:
                        logger.warning(f"Unexpected section type: {type(section)}")

        except Exception as e:
            logger.error(f"Error analyzing sections: {e}")

        return sections_info

    def _analyze_single_section(self, section: dict[str, Any]) -> dict[str, Any]:
        """Analyze a single section"""
        analysis = {
            "name": str(section.get("name", "unknown")),
            "virtual_address": section.get("vaddr", 0),
            "virtual_size": section.get("vsize", 0),
            "raw_size": section.get("size", 0),
            "flags": section.get("flags", ""),
            "entropy": 0.0,
            "is_executable": False,
            "is_writable": False,
            "is_readable": False,
            "suspicious_indicators": [],
            "characteristics": {},
            "pe_characteristics": [],
            "size_ratio": 0.0,
        }

        try:
            self._apply_permissions(section, analysis)
            self._apply_pe_characteristics(section, analysis)
            analysis["size_ratio"] = self._calculate_size_ratio(analysis)
            analysis["entropy"] = self._calculate_entropy(section)
            analysis["suspicious_indicators"] = self._check_suspicious_characteristics(
                section, analysis
            )
            analysis["characteristics"] = self._get_section_characteristics(section, analysis)

        except Exception as e:
            logger.error(f"Error in single section analysis: {e}")
            analysis["error"] = str(e)

        return analysis

    def _apply_permissions(self, section: dict[str, Any], analysis: dict[str, Any]) -> None:
        flags = str(section.get("flags", ""))
        analysis["is_executable"] = "x" in flags
        analysis["is_writable"] = "w" in flags
        analysis["is_readable"] = "r" in flags

        pe_flags = section.get("perm", "")
        if pe_flags:
            analysis["is_executable"] = analysis["is_executable"] or "x" in pe_flags
            analysis["is_writable"] = analysis["is_writable"] or "w" in pe_flags
            analysis["is_readable"] = analysis["is_readable"] or "r" in pe_flags

    def _apply_pe_characteristics(self, section: dict[str, Any], analysis: dict[str, Any]) -> None:
        characteristics_value = section.get("characteristics", 0)
        if not isinstance(characteristics_value, int) or characteristics_value <= 0:
            return
        analysis["pe_characteristics"] = self._decode_pe_characteristics(characteristics_value)
        if "IMAGE_SCN_MEM_EXECUTE" in analysis["pe_characteristics"]:
            analysis["is_executable"] = True
        if "IMAGE_SCN_MEM_WRITE" in analysis["pe_characteristics"]:
            analysis["is_writable"] = True
        if "IMAGE_SCN_MEM_READ" in analysis["pe_characteristics"]:
            analysis["is_readable"] = True

    def _calculate_size_ratio(self, analysis: dict[str, Any]) -> float:
        vsize = analysis.get("virtual_size", 0)
        raw_size = analysis.get("raw_size", 0)
        if raw_size <= 0:
            return 0.0
        return vsize / raw_size if vsize > 0 else 0.0

    def _calculate_entropy(self, section: dict[str, Any]) -> float:
        """Calculate Shannon entropy for section"""
        try:
            vaddr = section.get("vaddr", 0)
            size = section.get("size", 0)

            if size == 0 or size > 50000000:  # Skip very large sections (50MB)
                return 0.0

            # Read section data (limit to 1MB for performance)
            read_size = min(size, 1048576)
            data_cmd = f"p8 {read_size} @ {vaddr}"
            hex_data = self.r2.cmd(data_cmd)

            if not hex_data or not hex_data.strip():
                return 0.0

            try:
                data = bytes.fromhex(hex_data.strip())
            except ValueError:
                return 0.0

            if len(data) == 0:
                return 0.0

            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate Shannon entropy
            entropy = 0.0
            data_len = len(data)

            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)

            return entropy

        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0.0

    def _check_suspicious_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> list[str]:
        """Check for suspicious section characteristics"""
        indicators = []

        try:
            name = str(section.get("name", ""))
            vsize = section.get("vsize", 0)
            raw_size = section.get("size", 0)
            entropy = analysis.get("entropy", 0)

            indicators.extend(self._check_section_name_indicators(name))
            indicators.extend(self._check_permission_indicators(analysis))
            indicators.extend(self._check_entropy_indicators(entropy))
            indicators.extend(self._check_size_indicators(vsize, raw_size))

        except Exception as e:
            logger.error(f"Error checking suspicious characteristics: {e}")

        return indicators

    def _check_section_name_indicators(self, name: str) -> list[str]:
        """Check for suspicious section name indicators"""
        indicators = []

        # Check for non-standard section names
        if (
            isinstance(name, str)
            and name not in self.standard_sections
            and not name.startswith(".")
        ):
            indicators.append("Non-standard section name")

        # Check for suspicious section names
        suspicious_names = [
            "upx",
            "aspack",
            "themida",
            "vmprotect",
            "armadillo",
            "fsg",
            "petite",
            "mew",
            "packed",
            "crypted",
        ]

        if isinstance(name, str):
            for sus_name in suspicious_names:
                if sus_name in name.lower():
                    indicators.append(f"Suspicious section name: {sus_name}")
                    break

        return indicators

    def _check_permission_indicators(self, analysis: dict[str, Any]) -> list[str]:
        """Check for suspicious permission indicators"""
        indicators = []

        if analysis["is_writable"] and analysis["is_executable"]:
            indicators.append("Writable and executable section")

        if analysis["is_executable"] and analysis.get("entropy", 0) < 1.0:
            indicators.append("Executable section with very low entropy")

        return indicators

    def _check_entropy_indicators(self, entropy: float) -> list[str]:
        """Check for entropy-based indicators"""
        indicators = []

        if entropy > 7.5:
            indicators.append(f"High entropy ({entropy:.2f})")
        elif entropy > 7.0:
            indicators.append(f"Moderate high entropy ({entropy:.2f})")

        return indicators

    def _check_size_indicators(self, vsize: int, raw_size: int) -> list[str]:
        """Check for size-based indicators"""
        indicators = []

        # Check for large virtual vs raw size difference
        if vsize > 0 and raw_size > 0:
            ratio = vsize / raw_size
            size_diff_ratio = abs(vsize - raw_size) / max(vsize, raw_size)

            if ratio > 10:
                indicators.append(f"Suspicious size ratio: Virtual {ratio:.1f}x larger than raw")
            elif ratio > 5:
                indicators.append(f"Large size ratio: Virtual {ratio:.1f}x larger than raw")
            elif size_diff_ratio > 0.8:
                indicators.append(f"Large virtual/raw size difference ({size_diff_ratio:.1f})")

        # Check for very small sections
        if raw_size < 100 and raw_size > 0:
            indicators.append("Very small section")

        # Check for very large sections (>50MB)
        if raw_size > 52428800:
            indicators.append("Very large section")

        return indicators

    def _decode_pe_characteristics(self, characteristics: int) -> list[str]:
        """Decode PE section characteristics flags"""
        flags = []

        # PE section characteristics constants
        pe_flags = {
            0x00000020: "IMAGE_SCN_CNT_CODE",
            0x00000040: "IMAGE_SCN_CNT_INITIALIZED_DATA",
            0x00000080: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
            0x00000200: "IMAGE_SCN_LNK_INFO",
            0x00000800: "IMAGE_SCN_LNK_REMOVE",
            0x00001000: "IMAGE_SCN_LNK_COMDAT",
            0x00008000: "IMAGE_SCN_GPREL",
            0x00020000: "IMAGE_SCN_MEM_PURGEABLE",
            0x00040000: "IMAGE_SCN_MEM_16BIT",
            0x00080000: "IMAGE_SCN_MEM_LOCKED",
            0x00100000: "IMAGE_SCN_MEM_PRELOAD",
            0x01000000: "IMAGE_SCN_MEM_EXECUTE",
            0x02000000: "IMAGE_SCN_MEM_READ",
            0x04000000: "IMAGE_SCN_MEM_WRITE",
            0x08000000: "IMAGE_SCN_MEM_SHARED",
            0x10000000: "IMAGE_SCN_MEM_NOT_CACHED",
            0x20000000: "IMAGE_SCN_MEM_NOT_PAGED",
            0x40000000: "IMAGE_SCN_MEM_DISCARDABLE",
        }

        for flag_value, flag_name in pe_flags.items():
            if characteristics & flag_value:
                flags.append(flag_name)

        return flags

    def _get_section_characteristics(
        self, section: dict[str, Any], analysis: dict[str, Any]
    ) -> dict[str, Any]:
        """Get detailed section characteristics"""
        characteristics: dict[str, Any] = {}

        try:
            name = str(section.get("name", ""))

            # Define section mappings
            section_mappings = {
                ".text": ("Executable code", "6.0-7.5"),
                ".data": ("Initialized data", "3.0-6.0"),
                ".rdata": ("Read-only data", "4.0-6.5"),
                ".bss": ("Uninitialized data", "0.0-1.0"),
                ".rsrc": ("Resources", "2.0-7.0"),
                ".idata": ("Import data", "3.0-5.0"),
                ".edata": ("Export data", "3.0-5.0"),
                ".reloc": ("Relocations", "2.0-4.0"),
            }

            # Get characteristics from mapping or use defaults
            purpose, expected_entropy = section_mappings.get(name, ("Unknown/Custom", "Variable"))
            characteristics["purpose"] = purpose
            characteristics["expected_entropy"] = expected_entropy

            # Check entropy anomaly
            self._check_entropy_anomaly(characteristics, analysis)

            # Additional analysis for executable sections
            if analysis["is_executable"]:
                characteristics["code_analysis"] = self._analyze_code_section(section)

        except Exception as e:
            logger.error(f"Error getting section characteristics: {e}")

        return characteristics

    def _check_entropy_anomaly(self, characteristics: dict, analysis: dict) -> None:
        """Check if entropy is within expected range"""
        if characteristics["expected_entropy"] == "Variable":
            return

        try:
            entropy = analysis.get("entropy", 0)
            min_entropy, max_entropy = map(float, characteristics["expected_entropy"].split("-"))
            if entropy < min_entropy or entropy > max_entropy:
                characteristics["entropy_anomaly"] = True
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse entropy range: {e}")

    def _analyze_code_section(self, section: dict[str, Any]) -> dict[str, Any]:
        """Analyze executable code sections"""
        code_info: dict[str, Any] = {}

        try:
            vaddr = section.get("vaddr", 0)
            size = section.get("size", 0)

            if size == 0:
                return code_info

            # Get function count in this section
            functions_cmd = f"aflj @ {vaddr}"
            functions = safe_cmdj(self.r2, functions_cmd, [])

            if functions and isinstance(functions, list):
                code_info["function_count"] = len(functions)

                # Analyze function characteristics
                if len(functions) > 0:
                    # Ensure each function is a dict
                    sizes = [
                        f.get("size", 0)
                        for f in functions
                        if isinstance(f, dict) and f.get("size", 0) > 0
                    ]
                    if sizes:
                        code_info["avg_function_size"] = sum(sizes) / len(sizes)
                        code_info["min_function_size"] = min(sizes)
                        code_info["max_function_size"] = max(sizes)
            else:
                code_info["function_count"] = 0

            # Check for NOP sleds or padding
            nop_count = (
                len(safe_cmd(self.r2, f"/c nop @ {vaddr}").strip().split("\n"))
                if safe_cmd(self.r2, f"/c nop @ {vaddr}").strip()
                else 0
            )

            if nop_count > size / 100:  # More than 1% NOPs
                code_info["excessive_nops"] = True
                code_info["nop_ratio"] = nop_count / (size / 4)  # Approximate instruction count

        except Exception as e:
            logger.error(f"Error analyzing code section: {e}")

        return code_info

    def get_section_summary(self) -> dict[str, Any]:
        """Get summary of all sections"""
        summary: dict[str, Any] = {
            "total_sections": 0,
            "executable_sections": 0,
            "writable_sections": 0,
            "suspicious_sections": 0,
            "high_entropy_sections": 0,
            "avg_entropy": 0.0,
            "section_flags_summary": {},
        }

        try:
            sections_info = self.analyze_sections()

            if sections_info:
                summary["total_sections"] = len(sections_info)

                total_entropy = 0
                flag_counts: dict[str, int] = {}

                for section in sections_info:
                    total_entropy += self._update_summary_for_section(summary, section, flag_counts)

                summary["avg_entropy"] = total_entropy / len(sections_info)
                summary["section_flags_summary"] = flag_counts

        except Exception as e:
            logger.error(f"Error getting section summary: {e}")

        return summary

    def _update_summary_for_section(
        self,
        summary: dict[str, Any],
        section: dict[str, Any],
        flag_counts: dict[str, int],
    ) -> float:
        if section.get("is_executable"):
            summary["executable_sections"] += 1
        if section.get("is_writable"):
            summary["writable_sections"] += 1
        if section.get("suspicious_indicators"):
            summary["suspicious_sections"] += 1

        entropy = section.get("entropy", 0)
        if entropy > 7.0:
            summary["high_entropy_sections"] += 1

        flags = section.get("flags", "")
        flag_counts[flags] = flag_counts.get(flags, 0) + 1

        return entropy
