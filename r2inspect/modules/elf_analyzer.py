#!/usr/bin/env python3
"""ELF analysis module."""

import re
from typing import Any, cast

from ..abstractions import BaseAnalyzer
from ..utils.command_helpers import cmd as cmd_helper
from ..utils.command_helpers import cmd_list as cmd_list_helper
from ..utils.logger import get_logger
from ..utils.r2_helpers import get_elf_headers
from .elf_domain import (
    find_section_by_name,
    parse_build_id_data,
    parse_comment_compiler_info,
    parse_dwarf_compile_time,
    parse_dwarf_info,
    parse_dwarf_producer,
)
from .elf_security import get_security_features as _get_security_features

logger = get_logger(__name__)


class ELFAnalyzer(BaseAnalyzer):
    """ELF file analysis using radare2"""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        super().__init__(adapter=adapter, config=config)

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
        info: dict[str, Any] = {}

        try:
            # Get ELF information from radare2
            elf_info = self.adapter.get_file_info()

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
        info: dict[str, Any] = {}

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
        info: dict[str, Any] = {}

        try:
            sections = self._cmd_list("iSj")
            comment_section = find_section_by_name(sections, ".comment")
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
        info: dict[str, Any] = {}

        try:
            # Check if debug info is available
            debug_info = cmd_helper(self.adapter, self.r2, "id")

            if debug_info and "No debug info" not in debug_info:
                info.update(self._parse_dwarf_info(debug_info.split("\n")))

        except Exception as e:
            logger.error(f"Error extracting DWARF info: {e}")

        return info

    def _extract_build_id(self) -> str | None:
        """Extract build ID from .note.gnu.build-id section"""
        try:
            # Get sections information
            sections = self._cmd_list("iSj")
            build_id_section = find_section_by_name(sections, ".note.gnu.build-id")
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
            sections_info = self._cmd_list("iSj")

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
        return _get_security_features(self.adapter, logger)

    def _read_section(self, section: dict[str, Any] | None, cmd: str) -> str | None:
        if not section:
            return None
        if self.adapter is None or not hasattr(self.adapter, "read_bytes"):
            return None
        vaddr = section.get("vaddr", 0)
        size = section.get("size", 0)
        if not vaddr or not size:
            return None
        data = cast(bytes, self.adapter.read_bytes(vaddr, size))
        if cmd == "psz":
            return data.split(b"\x00", 1)[0].decode(errors="ignore")
        if cmd == "px":
            return " ".join(f"{byte:02x}" for byte in data)
        return data.decode(errors="ignore")

    def _parse_comment_compiler_info(self, comment_data: str) -> dict[str, Any]:
        return parse_comment_compiler_info(comment_data)

    def _parse_dwarf_info(self, dwarf_lines: list[str]) -> dict[str, Any]:
        return parse_dwarf_info(dwarf_lines)

    def _parse_dwarf_producer(self, line: str) -> dict[str, Any] | None:
        return parse_dwarf_producer(line)

    def _parse_dwarf_compile_time(self, line: str) -> str | None:
        return parse_dwarf_compile_time(line)

    def _parse_build_id_data(self, build_id_data: str | None) -> str | None:
        return parse_build_id_data(build_id_data)

    def _cmd_list(self, command: str) -> list[Any]:
        return cmd_list_helper(self.adapter, self.r2, command)
