#!/usr/bin/env python3
"""PE analysis module."""

from typing import Any

from ..abstractions import BaseAnalyzer
from ..registry import create_default_registry
from ..utils.logger import get_logger
from .pe_imports import calculate_imphash as _calculate_imphash
from .pe_info import get_compilation_info as _get_compilation_info
from .pe_info import get_file_characteristics as _get_file_characteristics
from .pe_info import get_pe_headers_info as _get_pe_headers_info
from .pe_info import get_subsystem_info as _get_subsystem_info
from .pe_info_domain import determine_pe_format as _determine_pe_format
from .pe_resources import get_resource_info as _get_resource_info
from .pe_resources import get_version_info as _get_version_info
from .pe_security import get_security_features as _get_security_features

logger = get_logger(__name__)

# Constants


class PEAnalyzer(BaseAnalyzer):
    """PE file analysis using radare2"""

    def __init__(
        self, adapter: Any, config: Any | None = None, filepath: str | None = None
    ) -> None:
        super().__init__(adapter=adapter, config=config, filepath=filepath)

    def get_category(self) -> str:
        return "format"

    def get_description(self) -> str:
        return "Comprehensive analysis of PE (Portable Executable) format including headers, security features, and embedded analyzers"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32", "PE32+", "DLL", "EXE"}

    def analyze(self) -> dict[str, Any]:
        """Perform complete PE analysis"""
        result = self._init_result_structure(
            {
                "architecture": "Unknown",
                "bits": 0,
                "type": "Unknown",
                "format": "PE",
                "security_features": {},
                "imphash": "",
            }
        )

        try:
            self._log_info("Starting PE analysis")

            filepath_str = str(self.filepath) if self.filepath is not None else None

            # Get PE headers information
            result.update(_get_pe_headers_info(self.adapter, filepath_str, logger))

            # Get file characteristics
            result.update(_get_file_characteristics(self.adapter, filepath_str, logger))

            # Get compilation info
            result.update(_get_compilation_info(self.adapter, logger))

            # Get security features
            result["security_features"] = self.get_security_features()

            # Get subsystem info
            result.update(_get_subsystem_info(self.adapter, logger))

            # Calculate imphash
            result["imphash"] = self.calculate_imphash()

            # Get registry for dynamic analyzer lookup
            registry = create_default_registry()

            self._run_optional_analyzers(result, registry)

            result["available"] = True
            self._log_info("PE analysis completed successfully")

        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"PE analysis failed: {e}")

        return result

    def _run_optional_analyzers(self, result: dict[str, Any], registry: Any) -> None:
        analyzers = [
            ("analyze_authenticode", "authenticode", "authenticode"),
            ("analyze_overlay", "overlay_analyzer", "overlay"),
            ("analyze_resources", "resource_analyzer", "resources"),
            ("analyze_mitigations", "exploit_mitigation", "exploit_mitigations"),
        ]

        for config_key, analyzer_name, result_key in analyzers:
            if not getattr(self.config, config_key, False):
                continue
            analyzer_class = registry.get_analyzer_class(analyzer_name)
            if not analyzer_class:
                continue
            analyzer = analyzer_class(self.adapter)
            result[result_key] = analyzer.analyze()

    def get_security_features(self) -> dict[str, bool]:
        """Check for security features by reading DllCharacteristics flags"""
        return _get_security_features(self.adapter, logger)

    def get_resource_info(self) -> list[dict[str, Any]]:
        """Get resource information"""
        return _get_resource_info(self.adapter, logger)

    def get_version_info(self) -> dict[str, str]:
        """Get version information from resources"""
        return _get_version_info(self.adapter, logger)

    def calculate_imphash(self) -> str:
        """Calculate Import Hash (imphash) for PE files.

        This implementation follows the exact algorithm used by pefile library:
        https://github.com/erocarrera/pefile/blob/master/pefile.py

        Returns:
            str: MD5 hash of normalized import names, or empty string if no imports
        """
        return _calculate_imphash(self.adapter, logger)

    def _determine_pe_format(
        self, bin_info: dict[str, Any], pe_header: dict[str, Any] | None
    ) -> str:
        return _determine_pe_format(bin_info, pe_header)
