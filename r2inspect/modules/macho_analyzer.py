#!/usr/bin/env python3
"""Mach-O analysis."""

import re
from typing import Any

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from ..infrastructure.r2_helpers import get_macho_headers
from .macho_domain import (
    build_load_commands,
    build_sections,
    dylib_timestamp_to_string,
    estimate_from_sdk_version,
    platform_from_version_min,
)
from .macho_security import get_security_features as _get_security_features

logger = get_logger(__name__)


class MachOAnalyzer(CommandHelperMixin, BaseAnalyzer):
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

        with self._analysis_context(result, error_message="Mach-O analysis failed"):
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

            self._log_info("Mach-O analysis completed successfully")

        return result

    def _get_macho_headers(self) -> dict[str, Any]:
        """Extract Mach-O header information."""

        def _load() -> dict[str, Any]:
            macho_info = self._cmdj("ij", {})
            if not (macho_info and "bin" in macho_info):
                return {}
            bin_info = macho_info["bin"]
            return {
                "architecture": bin_info.get("arch", "Unknown"),
                "machine": bin_info.get("machine", "Unknown"),
                "bits": bin_info.get("bits", 0),
                "endian": bin_info.get("endian", "Unknown"),
                "type": bin_info.get("class", "Unknown"),
                "format": bin_info.get("format", "Unknown"),
                "entry_point": bin_info.get("baddr", 0),
                "cpu_type": bin_info.get("cpu", "Unknown"),
                "file_type": bin_info.get("filetype", "Unknown"),
            }

        return self._safe_call(_load, default={}, error_msg="Error getting Mach-O headers")

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
            logger.error("Error getting compilation info: %s", e)

        return info

    def _extract_build_version(self) -> dict[str, Any]:
        """Extract build version information from LC_BUILD_VERSION."""

        def _load() -> dict[str, Any]:
            info: dict[str, Any] = {}
            for header in get_macho_headers(self.r2) or []:
                if header.get("type") != "LC_BUILD_VERSION":
                    continue
                info["platform"] = header.get("platform", "Unknown")
                info["min_os_version"] = header.get("minos", "Unknown")
                info["sdk_version"] = header.get("sdk", "Unknown")
                sdk_version = header.get("sdk", "")
                if sdk_version:
                    info["sdk_version_info"] = sdk_version
                    estimate = estimate_from_sdk_version(sdk_version)
                    if estimate:
                        info["compile_time"] = estimate
                break
            return info

        return self._safe_call(_load, default={}, error_msg="Error extracting build version")

    def _extract_version_min(self) -> dict[str, Any]:
        """Extract version minimum information from LC_VERSION_MIN_* commands."""

        def _load() -> dict[str, Any]:
            info: dict[str, Any] = {}
            for header in get_macho_headers(self.r2) or []:
                header_type = header.get("type", "")
                if "LC_VERSION_MIN" not in header_type:
                    continue
                info["version_min_type"] = header_type
                info["min_version"] = header.get("version", "Unknown")
                info["sdk_version"] = header.get("sdk", "Unknown")
                platform = platform_from_version_min(header_type)
                if platform:
                    info["platform"] = platform
                break
            return info

        return self._safe_call(_load, default={}, error_msg="Error extracting version min")

    def _extract_dylib_info(self) -> dict[str, Any]:
        """Extract dylib compilation information."""

        def _load() -> dict[str, Any]:
            info: dict[str, Any] = {}
            for header in get_macho_headers(self.r2) or []:
                if header.get("type") != "LC_ID_DYLIB":
                    continue
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
            return info

        return self._safe_call(_load, default={}, error_msg="Error extracting dylib info")

    def _extract_uuid(self) -> str | None:
        """Extract UUID from LC_UUID command."""

        def _load() -> str | None:
            for header in get_macho_headers(self.r2) or []:
                if header.get("type") == "LC_UUID":
                    uuid = header.get("uuid", "")
                    return str(uuid) if uuid else None
            return None

        return self._safe_call(_load, default=None, error_msg="Error extracting UUID")

    def _estimate_from_sdk_version(self, sdk_version: str) -> str | None:
        """Estimate compilation timeframe from SDK version."""
        return self._safe_call(
            lambda: estimate_from_sdk_version(sdk_version),
            default=None,
            error_msg="Error estimating from SDK version",
        )

    def _estimate_compile_time(self) -> str:
        """Estimate compile time as fallback"""
        # For Mach-O files without specific timestamp info
        return ""

    def _get_load_commands(self) -> list[dict[str, Any]]:
        """Get Mach-O load commands information."""
        return self._safe_call(
            lambda: build_load_commands(get_macho_headers(self.r2) or []),
            default=[],
            error_msg="Error getting load commands",
        )

    def _get_section_info(self) -> list[dict[str, Any]]:
        """Get Mach-O section information."""
        return self._safe_call(
            lambda: build_sections(
                [s for s in self._get_via_adapter("get_sections") if isinstance(s, dict)]
            ),
            default=[],
            error_msg="Error getting section info",
        )

    def get_security_features(self) -> dict[str, bool]:
        """Check for Mach-O security features"""
        return _get_security_features(self.adapter, logger)
