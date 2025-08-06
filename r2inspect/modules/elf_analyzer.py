#!/usr/bin/env python3
"""
ELF Analysis Module using r2pipe
"""

import re
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger
from ..utils.r2_helpers import get_elf_headers, safe_cmd_list, safe_cmdj

logger = get_logger(__name__)


class ELFAnalyzer:
    """ELF file analysis using radare2"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config

    def analyze(self) -> Dict[str, Any]:
        """Perform complete ELF analysis"""
        elf_info = {}

        try:
            # Get ELF headers information
            elf_info.update(self._get_elf_headers())

            # Get compilation info
            elf_info.update(self._get_compilation_info())

            # Get section information
            elf_info["sections"] = self._get_section_info()

            # Get program headers
            elf_info["program_headers"] = self._get_program_headers()

            # Get security features
            elf_info["security_features"] = self.get_security_features()

        except Exception as e:
            logger.error(f"Error in ELF analysis: {e}")
            elf_info["error"] = str(e)

        return elf_info

    def _get_elf_headers(self) -> Dict[str, Any]:
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

    def _get_compilation_info(self) -> Dict[str, Any]:
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

    def _extract_comment_section(self) -> Dict[str, Any]:
        """Extract information from .comment section"""
        info = {}

        try:
            # Get sections information
            sections = safe_cmd_list(self.r2, "iSj")

            for section in sections:
                if ".comment" in section.get("name", "").lower():
                    # Read the comment section content
                    vaddr = section.get("vaddr", 0)
                    size = section.get("size", 0)

                    if vaddr and size:
                        # Seek to the section and read its content
                        self.r2.cmd(f"s {vaddr}")
                        comment_data = self.r2.cmd(f"psz {size}")

                        if comment_data:
                            info["comment"] = comment_data.strip()

                            # Try to extract compiler information
                            compiler_match = re.search(
                                r"GCC:\s*\(([^)]+)\)\s*([0-9.]+)", comment_data
                            )
                            if compiler_match:
                                info["compiler"] = f"GCC {compiler_match.group(2)}"
                                info["compiler_version"] = compiler_match.group(2)
                                info["build_environment"] = compiler_match.group(1)

                            # Try to extract clang information
                            clang_match = re.search(r"clang\s+version\s+([0-9.]+)", comment_data)
                            if clang_match:
                                info["compiler"] = f"Clang {clang_match.group(1)}"
                                info["compiler_version"] = clang_match.group(1)

                    break

        except Exception as e:
            logger.error(f"Error extracting comment section: {e}")

        return info

    def _extract_dwarf_info(self) -> Dict[str, Any]:
        """Extract compilation info from DWARF debug information"""
        info = {}

        try:
            # Check if debug info is available
            debug_info = self.r2.cmd("id")

            if debug_info and "No debug info" not in debug_info:
                # Try to get DWARF compilation unit info
                dwarf_lines = debug_info.split("\n")

                for line in dwarf_lines:
                    # Look for DW_AT_producer (compiler info)
                    if "DW_AT_producer" in line:
                        # Extract compiler information
                        producer_match = re.search(r"DW_AT_producer\s*:\s*(.+)", line)
                        if producer_match:
                            producer = producer_match.group(1).strip()
                            info["dwarf_producer"] = producer

                            # Try to extract compiler from producer
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

                    # Look for compilation date/time (if available)
                    if "DW_AT_comp_dir" in line or "compilation" in line.lower():
                        # Sometimes compilation info includes timestamps
                        # Check for ISO date format first
                        date_match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                        if not date_match:
                            # Check for verbose date format
                            date_match = re.search(
                                r"(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})",
                                line,
                            )
                        if date_match:
                            info["compile_time"] = date_match.group(1)

        except Exception as e:
            logger.error(f"Error extracting DWARF info: {e}")

        return info

    def _extract_build_id(self) -> Optional[str]:
        """Extract build ID from .note.gnu.build-id section"""
        try:
            # Get sections information
            sections = safe_cmd_list(self.r2, "iSj")

            for section in sections:
                if ".note.gnu.build-id" in section.get("name", "").lower():
                    # Read the build-id section content
                    vaddr = section.get("vaddr", 0)
                    size = section.get("size", 0)

                    if vaddr and size:
                        # Seek to the section and read its content
                        self.r2.cmd(f"s {vaddr}")
                        build_id_data = self.r2.cmd(f"px {size}")

                        if build_id_data:
                            # Parse build ID (skip the note header, extract the hash)
                            lines = build_id_data.split("\n")
                            for line in lines:
                                if line.strip():
                                    # Extract hex bytes from the radare2 output
                                    hex_match = re.findall(r"([0-9a-fA-F]{2})", line)
                                    if len(hex_match) > 4:  # Skip note header
                                        return "".join(
                                            hex_match[4:]
                                        )  # Build ID starts after header

                    break

        except Exception as e:
            logger.error(f"Error extracting build ID: {e}")

        return None

    def _estimate_compile_time(self) -> str:
        """Estimate compile time as fallback (returns empty string for ELF)"""
        # For ELF files, we don't have a reliable way to get compile time
        # without specific debug info or comment sections
        return ""

    def _get_section_info(self) -> List[Dict[str, Any]]:
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

    def _get_program_headers(self) -> List[Dict[str, Any]]:
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

    def get_security_features(self) -> Dict[str, bool]:
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
            # Check for NX bit (No Execute)
            ph_info = get_elf_headers(self.r2)
            if ph_info:
                for header in ph_info:
                    if header.get("type") == "GNU_STACK":
                        flags = header.get("flags", "")
                        if "x" not in flags.lower():
                            features["nx"] = True
                        break

            # Check for stack canary
            symbols = safe_cmd_list(self.r2, "isj")
            if symbols:
                for symbol in symbols:
                    name = symbol.get("name", "")
                    if "__stack_chk_fail" in name or "__stack_chk_guard" in name:
                        features["stack_canary"] = True
                        break

            # Check for RELRO
            dynamic_info = self.r2.cmd("id")
            if "BIND_NOW" in dynamic_info:
                features["relro"] = True

            # Check for PIE (Position Independent Executable)
            elf_info = safe_cmdj(self.r2, "ij", {})
            if elf_info and "bin" in elf_info:
                elf_type = elf_info["bin"].get("class", "")
                if "DYN" in elf_type.upper():
                    features["pie"] = True

            # Check for RPATH/RUNPATH
            if "RPATH" in dynamic_info:
                features["rpath"] = True
            if "RUNPATH" in dynamic_info:
                features["runpath"] = True

        except Exception as e:
            logger.debug(f"Error checking security features: {e}")

        return features
