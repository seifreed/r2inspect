#!/usr/bin/env python3
import re
from typing import Any

from ..abstractions.coercion_support import coerce_int_or_none
from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from ..domain.formats.elf import (
    find_section_by_name,
    parse_build_id_data,
    parse_comment_compiler_info,
    parse_dwarf_info,
)
from .elf_security import get_security_features as _get_security_features

logger = get_logger(__name__)


def _format_section_bytes(data: bytes, cmd: str) -> str:
    if cmd == "psz":
        return data.split(b"\x00", 1)[0].decode(errors="ignore")
    if cmd == "px":
        return " ".join(f"{byte:02x}" for byte in data)
    return data.decode(errors="ignore")


class ELFAnalyzer(CommandHelperMixin, BaseAnalyzer):
    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        super().__init__(adapter=adapter, config=config)

    def get_category(self) -> str:
        return "format"

    def get_description(self) -> str:
        return "Comprehensive analysis of ELF binary format including headers, sections, and security features"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"ELF", "ELF32", "ELF64"}

    def analyze(self) -> dict[str, Any]:
        result = self._init_result_structure(
            {
                "architecture": "Unknown",
                "bits": 0,
                "sections": [],
                "program_headers": [],
                "security_features": {},
            }
        )

        with self._analysis_context(result, error_message="ELF analysis failed"):
            self._log_info("Starting ELF analysis")

            result.update(self._get_elf_headers())
            result.update(self._get_compilation_info())
            result["sections"] = self._get_section_info()
            result["program_headers"] = self._get_program_headers()
            result["security_features"] = self.get_security_features()

            self._log_info("ELF analysis completed successfully")

        return result

    def _get_elf_headers(self) -> dict[str, Any]:
        info: dict[str, Any] = {}

        try:
            # Get ELF information from radare2
            elf_info = self.adapter.get_file_info()

            if isinstance(elf_info, dict) and isinstance(elf_info.get("bin"), dict):
                bin_info = elf_info["bin"]

                info["architecture"] = bin_info.get("arch", "Unknown")
                info["machine"] = bin_info.get("machine", "Unknown")
                info["bits"] = coerce_int_or_none(bin_info.get("bits", 0)) or 0
                info["endian"] = bin_info.get("endian", "Unknown")
                info["type"] = bin_info.get("class", "Unknown")
                info["format"] = bin_info.get("format", "Unknown")
                info["entry_point"] = coerce_int_or_none(bin_info.get("baddr", 0)) or 0

        except Exception as e:
            logger.error("Error getting ELF headers: %s", e)

        return info

    def _get_compilation_info(self) -> dict[str, Any]:
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
            logger.error("Error getting compilation info: %s", e)

        return info

    def _extract_comment_section(self) -> dict[str, Any]:
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
            logger.error("Error extracting comment section: %s", e)

        return info

    def _extract_dwarf_info(self) -> dict[str, Any]:
        info: dict[str, Any] = {}

        try:
            # Check if debug info is available
            debug_info = self._cmd("id")

            if isinstance(debug_info, str) and debug_info and "No debug info" not in debug_info:
                info.update(self._parse_dwarf_info(debug_info.split("\n")))

        except Exception as e:
            logger.error("Error extracting DWARF info: %s", e)

        return info

    def _extract_build_id(self) -> str | None:
        try:
            sections = self._cmd_list("iSj")
            build_id_section = find_section_by_name(sections, ".note.gnu.build-id")
            if not build_id_section:
                return None

            build_id_data = self._read_section(build_id_section, "px")
            return self._parse_build_id_data(build_id_data)

        except Exception as e:
            logger.error("Error extracting build ID: %s", e)

        return None

    def _estimate_compile_time(self) -> str:
        return ""

    def _get_section_info(self) -> list[dict[str, Any]]:
        sections = []

        try:
            sections_info = self._cmd_list("iSj")

            if sections_info:
                for section in sections_info:
                    if not isinstance(section, dict):
                        continue
                    sections.append(
                        {
                            "name": section.get("name", "Unknown"),
                            "type": section.get("type", "Unknown"),
                            "flags": section.get("flags", ""),
                            "size": coerce_int_or_none(section.get("size", 0)),
                            "vaddr": coerce_int_or_none(section.get("vaddr", 0)),
                            "paddr": coerce_int_or_none(section.get("paddr", 0)),
                        }
                    )
            else:
                logger.debug("No sections found or invalid response from radare2")

        except Exception as e:
            logger.debug("Error getting section info: %s", e)

        return sections

    def _get_program_headers(self) -> list[dict[str, Any]]:
        """Get ELF program headers (segments) from radare2.

        Program headers are r2 "segments" (iSSj): PHDR, INTERP, LOAD*, DYNAMIC,
        etc. The previous code read the ELF *file* header (ih/ihj), whose fields
        (Type, Machine, PhOff, ...) carry none of the program-header keys below,
        so every entry came back as empty defaults.
        """
        headers: list[dict[str, Any]] = []
        for segment in self._cmd_list("iSSj"):
            if not isinstance(segment, dict):
                continue
            headers.append(
                {
                    "type": segment.get("name", "Unknown"),
                    "flags": segment.get("perm", ""),
                    "offset": segment.get("paddr", 0),
                    "vaddr": segment.get("vaddr", 0),
                    "paddr": segment.get("paddr", 0),
                    "filesz": segment.get("size", 0),
                    "memsz": segment.get("vsize", 0),
                }
            )
        return headers

    def get_security_features(self) -> dict[str, bool]:
        """Check for ELF security features"""
        return _get_security_features(self.adapter, logger)

    def _read_section(self, section: dict[str, Any] | None, cmd: str) -> str | None:
        if not section:
            return None
        if self.adapter is None or not hasattr(self.adapter, "read_bytes"):
            return None
        vaddr = coerce_int_or_none(section.get("vaddr", 0))
        size = coerce_int_or_none(section.get("size", 0))
        if not vaddr or not size:
            return None
        # An ELF section-header size is attacker-controlled, and these callers
        # only need small metadata (a compiler string, a build-id). Cap the read
        # so a crafted oversized section can't force a huge read + decode,
        # matching the section-analyzer read cap.
        read_size = min(size, 1024 * 1024)
        data = self.adapter.read_bytes(vaddr, read_size)
        if not isinstance(data, (bytes, bytearray)):
            return None
        return _format_section_bytes(data, cmd)

    def _parse_comment_compiler_info(self, comment_data: str) -> dict[str, Any]:
        return parse_comment_compiler_info(comment_data)

    def _parse_dwarf_info(self, dwarf_lines: list[str]) -> dict[str, Any]:
        return parse_dwarf_info(dwarf_lines)

    def _parse_build_id_data(self, build_id_data: str | None) -> str | None:
        return parse_build_id_data(build_id_data)


__all__ = [
    "re",
]
