#!/usr/bin/env python3
"""
ELF Analysis Module using r2pipe
"""

import re
from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import get_elf_headers, safe_cmd_list, safe_cmdj

logger = get_logger(__name__)


class ELFAnalyzer(BaseAnalyzer):
    """ELF file analysis using radare2"""

    def __init__(self, r2, config):
        super().__init__(r2=r2, config=config)

    def get_category(self) -> str:
        return "format"

    def get_description(self) -> str:
        return "Comprehensive analysis of ELF binary format including headers, sections, and security features"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"ELF", "ELF32", "ELF64"}

    def analyze(self) -> dict[str, Any]:
        """Perform complete ELF analysis"""
        result = self._init_result_structure(
            {
                "architecture": "Unknown",
                "bits": 0,
                "sections": [],
                "program_headers": [],
                "security_features": {},
            }
        )

        try:
            self._log_info("Starting ELF analysis")

            # Get ELF headers information
            result.update(self._get_elf_headers())

            # Get compilation info
            result.update(self._get_compilation_info())

            # Get section information
            result["sections"] = self._get_section_info()

            # Get program headers
            result["program_headers"] = self._get_program_headers()

            # Get security features
            result["security_features"] = self.get_security_features()

            result["available"] = True
            self._log_info("ELF analysis completed successfully")

        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"ELF analysis failed: {e}")

        return result

    def _get_elf_headers(self) -> dict[str, Any]:
        """Extract ELF header information"""
        info = {}

        try:
            # Get ELF information from radare2
            elf_info = safe_cmdj(self.r2, "ij", {})

            if elf_info and "bin" in elf_info:
                bin_info = elf_info["bin"]

                info["architecture"] = bin_info.get("arch", "Unknown")
                info["machine"] = bin_info.get("machine", "Unknown")
                info["bits"] = bin_info.get("bits", 0)
                info["endian"] = bin_info.get("endian", "Unknown")
                info["type"] = bin_info.get("class", "Unknown")
                info["format"] = bin_info.get("format", "Unknown")
                info["entry_point"] = bin_info.get("baddr", 0)

        except Exception as e:
            logger.error(f"Error getting ELF headers: {e}")

        return info

    def _get_compilation_info(self) -> dict[str, Any]:
        """Get compilation information from various ELF sources"""
        info = {}

        try:
            # Try to get compilation info from .comment section
            comment_info = self._extract_comment_section()
            if comment_info:
                info.update(comment_info)

            # Try to get DWARF compilation info (if not stripped)
            dwarf_info = self._extract_dwarf_info()
            if dwarf_info:
                info.update(dwarf_info)

            # Try to get build-id info
            build_id = self._extract_build_id()
            if build_id:
                info["build_id"] = build_id

            # If no specific compile time found, try to estimate
            if "compile_time" not in info:
                info["compile_time"] = self._estimate_compile_time()

        except Exception as e:
            logger.error(f"Error getting compilation info: {e}")

        return info

    def _extract_comment_section(self) -> dict[str, Any]:
        """Extract information from .comment section"""
        info = {}

        try:
            sections = safe_cmd_list(self.r2, "iSj")
            comment_section = self._find_section(sections, ".comment")
            if not comment_section:
                return info

            comment_data = self._read_section(comment_section, "psz")
            if not comment_data:
                return info

            info["comment"] = comment_data.strip()
            info.update(self._parse_comment_compiler_info(comment_data))

        except Exception as e:
            logger.error(f"Error extracting comment section: {e}")

        return info

    def _extract_dwarf_info(self) -> dict[str, Any]:
        """Extract compilation info from DWARF debug information"""
        info = {}

        try:
            # Check if debug info is available
            debug_info = self.r2.cmd("id")

            if debug_info and "No debug info" not in debug_info:
                info.update(self._parse_dwarf_info(debug_info.split("\n")))

        except Exception as e:
            logger.error(f"Error extracting DWARF info: {e}")

        return info

    def _extract_build_id(self) -> str | None:
        """Extract build ID from .note.gnu.build-id section"""
        try:
            # Get sections information
            sections = safe_cmd_list(self.r2, "iSj")
            build_id_section = self._find_section(sections, ".note.gnu.build-id")
            if not build_id_section:
                return None

            build_id_data = self._read_section(build_id_section, "px")
            return self._parse_build_id_data(build_id_data)

        except Exception as e:
            logger.error(f"Error extracting build ID: {e}")

        return None

    def _estimate_compile_time(self) -> str:
        """Estimate compile time as fallback (returns empty string for ELF)"""
        # For ELF files, we don't have a reliable way to get compile time
        # without specific debug info or comment sections
        return ""

    def _get_section_info(self) -> list[dict[str, Any]]:
        """Get ELF section information"""
        sections = []

        try:
            sections_info = safe_cmd_list(self.r2, "iSj")

            if sections_info:
                for section in sections_info:
                    sections.append(
                        {
                            "name": section.get("name", "Unknown"),
                            "type": section.get("type", "Unknown"),
                            "flags": section.get("flags", ""),
                            "size": section.get("size", 0),
                            "vaddr": section.get("vaddr", 0),
                            "paddr": section.get("paddr", 0),
                        }
                    )
            else:
                logger.debug("No sections found or invalid response from radare2")

        except Exception as e:
            logger.debug(f"Error getting section info: {e}")

        return sections

    def _get_program_headers(self) -> list[dict[str, Any]]:
        """Get ELF program headers information"""
        headers = []

        try:
            # Get program headers - iHj doesn't exist, use alternative
            # For ELF, we should use ih command instead
            ph_info = get_elf_headers(self.r2)

            if ph_info:
                for header in ph_info:
                    headers.append(
                        {
                            "type": header.get("type", "Unknown"),
                            "flags": header.get("flags", ""),
                            "offset": header.get("offset", 0),
                            "vaddr": header.get("vaddr", 0),
                            "paddr": header.get("paddr", 0),
                            "filesz": header.get("filesz", 0),
                            "memsz": header.get("memsz", 0),
                        }
                    )
            else:
                logger.debug("No program headers found or invalid response from radare2")

        except Exception as e:
            logger.debug(f"Error getting program headers: {e}")

        return headers

    def get_security_features(self) -> dict[str, bool]:
        """Check for ELF security features"""
        features = {
            "nx": False,
            "stack_canary": False,
            "relro": False,
            "pie": False,
            "rpath": False,
            "runpath": False,
        }

        try:
            self._check_nx(features)
            self._check_stack_canary(features)
            dynamic_info = self.r2.cmd("id")
            self._check_relro(features, dynamic_info)
            self._check_pie(features)
            self._check_paths(features, dynamic_info)

        except Exception as e:
            logger.debug(f"Error checking security features: {e}")

        return features

    def _find_section(self, sections: list[dict[str, Any]], name_substr: str) -> dict | None:
        name_substr = name_substr.lower()
        for section in sections or []:
            if name_substr in section.get("name", "").lower():
                return section
        return None

    def _read_section(self, section: dict[str, Any], cmd: str) -> str | None:
        vaddr = section.get("vaddr", 0)
        size = section.get("size", 0)
        if not vaddr or not size:
            return None
        self.r2.cmd(f"s {vaddr}")
        return self.r2.cmd(f"{cmd} {size}")

    def _parse_comment_compiler_info(self, comment_data: str) -> dict[str, Any]:
        info: dict[str, Any] = {}
        compiler_match = re.search(r"GCC:\s*\(([^)]+)\)\s*([0-9.]+)", comment_data)
        if compiler_match:
            info["compiler"] = f"GCC {compiler_match.group(2)}"
            info["compiler_version"] = compiler_match.group(2)
            info["build_environment"] = compiler_match.group(1)
        clang_match = re.search(r"clang\s+version\s+([0-9.]+)", comment_data)
        if clang_match:
            info["compiler"] = f"Clang {clang_match.group(1)}"
            info["compiler_version"] = clang_match.group(1)
        return info

    def _parse_dwarf_info(self, dwarf_lines: list[str]) -> dict[str, Any]:
        info: dict[str, Any] = {}
        for line in dwarf_lines:
            producer = self._parse_dwarf_producer(line)
            if producer:
                info.update(producer)
            compile_time = self._parse_dwarf_compile_time(line)
            if compile_time:
                info["compile_time"] = compile_time
        return info

    def _parse_dwarf_producer(self, line: str) -> dict[str, Any] | None:
        if "DW_AT_producer" not in line:
            return None
        producer_match = re.search(r"DW_AT_producer\s*:\s*(.+)", line)
        if not producer_match:
            return None
        producer = producer_match.group(1).strip()
        info: dict[str, Any] = {"dwarf_producer": producer}
        if "GNU C" in producer:
            gcc_match = re.search(r"GNU C\D*([0-9.]+)", producer)
            if gcc_match:
                info["compiler"] = f"GCC {gcc_match.group(1)}"
                info["compiler_version"] = gcc_match.group(1)
        elif "clang" in producer.lower():
            clang_match = re.search(r"clang\D*([0-9.]+)", producer)
            if clang_match:
                info["compiler"] = f"Clang {clang_match.group(1)}"
                info["compiler_version"] = clang_match.group(1)
        return info

    def _parse_dwarf_compile_time(self, line: str) -> str | None:
        if "DW_AT_comp_dir" not in line and "compilation" not in line.lower():
            return None
        date_match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
        if not date_match:
            date_match = re.search(
                r"(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})",
                line,
            )
        return date_match.group(1) if date_match else None

    def _parse_build_id_data(self, build_id_data: str | None) -> str | None:
        if not build_id_data:
            return None
        for line in build_id_data.split("\n"):
            if not line.strip():
                continue
            hex_match = re.findall(r"([0-9a-fA-F]{2})", line)
            if len(hex_match) > 4:
                return "".join(hex_match[4:])
        return None

    def _check_nx(self, features: dict[str, bool]) -> None:
        ph_info = get_elf_headers(self.r2)
        if not ph_info:
            return
        for header in ph_info:
            if header.get("type") == "GNU_STACK":
                flags = header.get("flags", "")
                if "x" not in flags.lower():
                    features["nx"] = True
                break

    def _check_stack_canary(self, features: dict[str, bool]) -> None:
        symbols = safe_cmd_list(self.r2, "isj")
        if not symbols:
            return
        for symbol in symbols:
            name = symbol.get("name", "")
            if "__stack_chk_fail" in name or "__stack_chk_guard" in name:
                features["stack_canary"] = True
                break

    def _check_relro(self, features: dict[str, bool], dynamic_info: str) -> None:
        if "BIND_NOW" in dynamic_info:
            features["relro"] = True

    def _check_pie(self, features: dict[str, bool]) -> None:
        elf_info = safe_cmdj(self.r2, "ij", {})
        if elf_info and "bin" in elf_info:
            elf_type = elf_info["bin"].get("class", "")
            if "DYN" in elf_type.upper():
                features["pie"] = True

    def _check_paths(self, features: dict[str, bool], dynamic_info: str) -> None:
        if "RPATH" in dynamic_info:
            features["rpath"] = True
        if "RUNPATH" in dynamic_info:
            features["runpath"] = True
