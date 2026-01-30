#!/usr/bin/env python3
# mypy: ignore-errors
"""
Mach-O Analysis Module using r2pipe
"""

import re
from datetime import datetime
from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import get_macho_headers, safe_cmdj

logger = get_logger(__name__)


class MachOAnalyzer(BaseAnalyzer):
    """Mach-O file analysis using radare2"""

    def __init__(self, r2, config):
        super().__init__(r2=r2, config=config)

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
            macho_info = safe_cmdj(self.r2, "ij")

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
            headers = get_macho_headers(self.r2)

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
                        # Could map SDK versions to release dates for estimation
                        compile_time_estimate = self._estimate_from_sdk_version(sdk_version)
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
            headers = get_macho_headers(self.r2)

            for header in headers:
                header_type = header.get("type", "")
                if "LC_VERSION_MIN" in header_type:
                    info["version_min_type"] = header_type
                    info["min_version"] = header.get("version", "Unknown")
                    info["sdk_version"] = header.get("sdk", "Unknown")

                    # Map the version min type to platform
                    if "MACOSX" in header_type:
                        info["platform"] = "macOS"
                    elif "IPHONEOS" in header_type:
                        info["platform"] = "iOS"
                    elif "TVOS" in header_type:
                        info["platform"] = "tvOS"
                    elif "WATCHOS" in header_type:
                        info["platform"] = "watchOS"

                    break

        except Exception as e:
            logger.error(f"Error extracting version min: {e}")

        return info

    def _extract_dylib_info(self) -> dict[str, Any]:
        """Extract dylib compilation information"""
        info = {}

        try:
            # Get load commands
            headers = get_macho_headers(self.r2)

            for header in headers:
                if header.get("type") == "LC_ID_DYLIB":
                    # Extract dylib timestamp
                    timestamp = header.get("timestamp", 0)
                    if timestamp and timestamp > 0:
                        # Convert timestamp to readable date
                        try:
                            compile_date = datetime.fromtimestamp(timestamp)
                            info["compile_time"] = compile_date.strftime("%a %b %d %H:%M:%S %Y")
                            info["dylib_timestamp"] = timestamp
                        except Exception:
                            info["dylib_timestamp"] = timestamp

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
            headers = get_macho_headers(self.r2)

            for header in headers:
                if header.get("type") == "LC_UUID":
                    uuid = header.get("uuid", "")
                    if uuid:
                        return uuid
                    break

        except Exception as e:
            logger.error(f"Error extracting UUID: {e}")

        return None

    def _estimate_from_sdk_version(self, sdk_version: str) -> str | None:
        """Estimate compilation timeframe from SDK version"""
        try:
            # Basic mapping of SDK versions to release timeframes
            # This is a simplified approach - in reality, you'd want a more comprehensive mapping
            sdk_mappings = {
                "10.15": "2019",  # macOS Catalina
                "11.0": "2020",  # macOS Big Sur
                "12.0": "2021",  # macOS Monterey
                "13.0": "2022",  # macOS Ventura
                "14.0": "2023",  # macOS Sonoma
                "15.0": "2024",  # macOS Sequoia
            }

            # Extract major.minor version
            version_match = re.search(r"(\d+\.\d+)", sdk_version)
            if version_match:
                version = version_match.group(1)
                if version in sdk_mappings:
                    return f"~{sdk_mappings[version]} (SDK {sdk_version})"

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
            headers = get_macho_headers(self.r2)

            for header in headers:
                commands.append(
                    {
                        "type": header.get("type", "Unknown"),
                        "size": header.get("size", 0),
                        "offset": header.get("offset", 0),
                        "data": header,  # Include full header data
                    }
                )

        except Exception as e:
            logger.error(f"Error getting load commands: {e}")

        return commands

    def _get_section_info(self) -> list[dict[str, Any]]:
        """Get Mach-O section information"""
        sections = []

        try:
            sections_info = safe_cmdj(self.r2, "iSj")

            for section in sections_info:
                sections.append(
                    {
                        "name": section.get("name", "Unknown"),
                        "segment": section.get("segment", "Unknown"),
                        "type": section.get("type", "Unknown"),
                        "flags": section.get("flags", ""),
                        "size": section.get("size", 0),
                        "vaddr": section.get("vaddr", 0),
                        "paddr": section.get("paddr", 0),
                    }
                )

        except Exception as e:
            logger.error(f"Error getting section info: {e}")

        return sections

    def get_security_features(self) -> dict[str, bool]:
        """Check for Mach-O security features"""
        features = {
            "pie": False,
            "nx": False,
            "stack_canary": False,
            "arc": False,
            "encrypted": False,
            "signed": False,
        }

        try:
            self._check_pie(features)
            symbols = safe_cmdj(self.r2, "isj")
            self._check_stack_canary(features, symbols)
            self._check_arc(features, symbols)
            headers = get_macho_headers(self.r2)
            self._check_encryption(features, headers)
            self._check_code_signature(features, headers)
            features["nx"] = True

        except Exception as e:
            logger.error(f"Error checking security features: {e}")

        return features

    def _check_pie(self, features: dict[str, bool]) -> None:
        macho_info = safe_cmdj(self.r2, "ij")
        if macho_info and "bin" in macho_info:
            file_type = macho_info["bin"].get("filetype", "")
            if "DYLIB" in file_type.upper() or "PIE" in file_type.upper():
                features["pie"] = True

    def _check_stack_canary(self, features: dict[str, bool], symbols: list[dict[str, Any]]):
        for symbol in symbols or []:
            name = symbol.get("name", "")
            if "___stack_chk_fail" in name or "___stack_chk_guard" in name:
                features["stack_canary"] = True
                break

    def _check_arc(self, features: dict[str, bool], symbols: list[dict[str, Any]]):
        for symbol in symbols or []:
            name = symbol.get("name", "")
            if "_objc_" in name and ("retain" in name or "release" in name):
                features["arc"] = True
                break

    def _check_encryption(self, features: dict[str, bool], headers: list[dict[str, Any]]):
        for header in headers or []:
            if header.get("type") in {"LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64"}:
                cryptid = header.get("cryptid", 0)
                if cryptid > 0:
                    features["encrypted"] = True
                break

    def _check_code_signature(self, features: dict[str, bool], headers: list[dict[str, Any]]):
        for header in headers or []:
            if header.get("type") == "LC_CODE_SIGNATURE":
                features["signed"] = True
                break
