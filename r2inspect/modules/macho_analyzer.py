#!/usr/bin/env python3
"""Mach-O analysis."""

import re
from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.command_helpers import cmdj as cmdj_helper
from ..utils.logger import get_logger
from ..utils.r2_helpers import get_macho_headers
from .macho_domain import (
    build_load_commands,
    build_sections,
    dylib_timestamp_to_string,
    estimate_from_sdk_version,
    platform_from_version_min,
)
from .macho_security import get_security_features as _get_security_features

logger = get_logger(__name__)


class MachOAnalyzer(BaseAnalyzer):
    """Mach-O file analysis using radare2"""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        super().__init__(adapter=adapter, config=config)

    def get_category(self) -> str:
        return "format"

    def get_description(self) -> str:
        return "Comprehensive analysis of Mach-O binary format for macOS/iOS including load commands and security features"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"MACH0", "MACHO", "MACH-O", "MACH064"}

    def analyze(self) -> dict[str, Any]:
        """Perform complete Mach-O analysis"""
        result = self._init_result_structure(
            {
                "architecture": "Unknown",
                "bits": 0,
                "load_commands": [],
                "sections": [],
                "security_features": {},
            }
        )

        try:
            self._log_info("Starting Mach-O analysis")

            # Get Mach-O headers information
            result.update(self._get_macho_headers())

            # Get compilation info
            result.update(self._get_compilation_info())

            # Get load commands
            result["load_commands"] = self._get_load_commands()

            # Get section information
            result["sections"] = self._get_section_info()

            # Get security features
            result["security_features"] = self.get_security_features()

            result["available"] = True
            self._log_info("Mach-O analysis completed successfully")

        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"Mach-O analysis failed: {e}")

        return result

    def _get_macho_headers(self) -> dict[str, Any]:
        """Extract Mach-O header information"""
        info = {}

        try:
            # Get Mach-O information from radare2
            macho_info = self._cmdj("ij", {})

            if macho_info and "bin" in macho_info:
                bin_info = macho_info["bin"]

                info["architecture"] = bin_info.get("arch", "Unknown")
                info["machine"] = bin_info.get("machine", "Unknown")
                info["bits"] = bin_info.get("bits", 0)
                info["endian"] = bin_info.get("endian", "Unknown")
                info["type"] = bin_info.get("class", "Unknown")
                info["format"] = bin_info.get("format", "Unknown")
                info["entry_point"] = bin_info.get("baddr", 0)

                # Mach-O specific fields
                info["cpu_type"] = bin_info.get("cpu", "Unknown")
                info["file_type"] = bin_info.get("filetype", "Unknown")

        except Exception as e:
            logger.error(f"Error getting Mach-O headers: {e}")

        return info

    def _get_compilation_info(self) -> dict[str, Any]:
        """Get compilation information from Mach-O load commands"""
        info = {}

        try:
            # Try to get build version info
            build_version = self._extract_build_version()
            if build_version:
                info.update(build_version)

            # Try to get version min info
            version_min = self._extract_version_min()
            if version_min:
                info.update(version_min)

            # Try to get dylib info
            dylib_info = self._extract_dylib_info()
            if dylib_info:
                info.update(dylib_info)

            # Try to get UUID (build identifier)
            uuid = self._extract_uuid()
            if uuid:
                info["uuid"] = uuid

            # If no specific compile time found, try to estimate
            if "compile_time" not in info:
                info["compile_time"] = self._estimate_compile_time()

        except Exception as e:
            logger.error(f"Error getting compilation info: {e}")

        return info

    def _extract_build_version(self) -> dict[str, Any]:
        """Extract build version information from LC_BUILD_VERSION"""
        info = {}

        try:
            # Get load commands
            headers = get_macho_headers(self.r2) or []

            for header in headers:
                if header.get("type") == "LC_BUILD_VERSION":
                    # Extract build version information
                    info["platform"] = header.get("platform", "Unknown")
                    info["min_os_version"] = header.get("minos", "Unknown")
                    info["sdk_version"] = header.get("sdk", "Unknown")

                    # Try to infer compilation timeframe from SDK version
                    sdk_version = header.get("sdk", "")
                    if sdk_version:
                        info["sdk_version_info"] = sdk_version
                        compile_time_estimate = estimate_from_sdk_version(sdk_version)
                        if compile_time_estimate:
                            info["compile_time"] = compile_time_estimate

                    break

        except Exception as e:
            logger.error(f"Error extracting build version: {e}")

        return info

    def _extract_version_min(self) -> dict[str, Any]:
        """Extract version minimum information from LC_VERSION_MIN_* commands"""
        info = {}

        try:
            # Get load commands
            headers = get_macho_headers(self.r2) or []

            for header in headers:
                header_type = header.get("type", "")
                if "LC_VERSION_MIN" in header_type:
                    info["version_min_type"] = header_type
                    info["min_version"] = header.get("version", "Unknown")
                    info["sdk_version"] = header.get("sdk", "Unknown")

                    # Map the version min type to platform
                    platform = platform_from_version_min(header_type)
                    if platform:
                        info["platform"] = platform

                    break

        except Exception as e:
            logger.error(f"Error extracting version min: {e}")

        return info

    def _extract_dylib_info(self) -> dict[str, Any]:
        """Extract dylib compilation information"""
        info = {}

        try:
            # Get load commands
            headers = get_macho_headers(self.r2) or []

            for header in headers:
                if header.get("type") == "LC_ID_DYLIB":
                    # Extract dylib timestamp
                    timestamp = header.get("timestamp", 0)
                    compile_time, raw_timestamp = dylib_timestamp_to_string(timestamp)
                    if compile_time:
                        info["compile_time"] = compile_time
                    if raw_timestamp:
                        info["dylib_timestamp"] = str(raw_timestamp)

                    info["dylib_name"] = header.get("name", "Unknown")
                    info["dylib_version"] = header.get("version", "Unknown")
                    info["dylib_compatibility"] = header.get("compatibility", "Unknown")

                    break

        except Exception as e:
            logger.error(f"Error extracting dylib info: {e}")

        return info

    def _extract_uuid(self) -> str | None:
        """Extract UUID from LC_UUID command"""
        try:
            # Get load commands
            headers = get_macho_headers(self.r2) or []

            for header in headers:
                if header.get("type") == "LC_UUID":
                    uuid = header.get("uuid", "")
                    if uuid:
                        return str(uuid)
                    break

        except Exception as e:
            logger.error(f"Error extracting UUID: {e}")

        return None

    def _estimate_from_sdk_version(self, sdk_version: str) -> str | None:
        """Estimate compilation timeframe from SDK version"""
        try:
            return estimate_from_sdk_version(sdk_version)

        except Exception as e:
            logger.error(f"Error estimating from SDK version: {e}")

        return None

    def _estimate_compile_time(self) -> str:
        """Estimate compile time as fallback"""
        # For Mach-O files without specific timestamp info
        return ""

    def _get_load_commands(self) -> list[dict[str, Any]]:
        """Get Mach-O load commands information"""
        commands = []

        try:
            headers = get_macho_headers(self.r2) or []
            commands = build_load_commands(headers)

        except Exception as e:
            logger.error(f"Error getting load commands: {e}")

        return commands

    def _get_section_info(self) -> list[dict[str, Any]]:
        """Get Mach-O section information"""
        sections = []

        try:
            if self.adapter is not None and hasattr(self.adapter, "get_sections"):
                sections_info = self.adapter.get_sections()
            else:
                sections_info = []
            sections = build_sections(sections_info if isinstance(sections_info, list) else [])

        except Exception as e:
            logger.error(f"Error getting section info: {e}")

        return sections

    def get_security_features(self) -> dict[str, bool]:
        """Check for Mach-O security features"""
        return _get_security_features(self.adapter, logger)

    def _cmdj(self, command: str, default: Any) -> Any:
        return cmdj_helper(self.adapter, self.r2, command, default)
