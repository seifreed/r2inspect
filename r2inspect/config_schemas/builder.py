#!/usr/bin/env python3
"""
r2inspect Configuration Builder - Fluent API for Configuration Construction
Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

from .schemas import (
    AnalysisConfig,
    CryptoConfig,
    GeneralConfig,
    OutputConfig,
    PackerConfig,
    PEAnalysisConfig,
    R2InspectConfig,
    StringsConfig,
    VirusTotalConfig,
    YaraConfig,
)


class ConfigBuilder:
    """
    Fluent API builder for R2InspectConfig.

    Provides a chainable interface for constructing configurations.

    Example:
        config = (ConfigBuilder()
                  .with_verbose(True)
                  .with_yara_enabled(True)
                  .with_virustotal("api_key_here")
                  .build())
    """

    def __init__(self):
        """Initialize builder with default values"""
        self._general_kwargs = {}
        self._yara_kwargs = {}
        self._packer_kwargs = {}
        self._crypto_kwargs = {}
        self._strings_kwargs = {}
        self._output_kwargs = {}
        self._virustotal_kwargs = {}
        self._analysis_kwargs = {}
        self._pe_analysis_kwargs = {}

    # General Configuration Methods
    def with_verbose(self, verbose: bool = True) -> "ConfigBuilder":
        """Enable or disable verbose output"""
        self._general_kwargs["verbose"] = verbose
        return self

    def with_max_strings(self, max_strings: int) -> "ConfigBuilder":
        """Set maximum number of strings to extract"""
        self._general_kwargs["max_strings"] = max_strings
        return self

    def with_string_length_range(self, min_length: int, max_length: int) -> "ConfigBuilder":
        """Set string length range for extraction"""
        self._general_kwargs["min_string_length"] = min_length
        self._general_kwargs["max_string_length"] = max_length
        return self

    # YARA Configuration Methods
    def with_yara_rules(self, rules_path: str) -> "ConfigBuilder":
        """Set YARA rules path"""
        self._yara_kwargs["rules_path"] = rules_path
        return self

    def with_yara_enabled(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable YARA scanning"""
        self._yara_kwargs["enabled"] = enabled
        return self

    def with_yara_timeout(self, timeout: int) -> "ConfigBuilder":
        """Set YARA scan timeout in seconds"""
        self._yara_kwargs["timeout"] = timeout
        return self

    # Packer Configuration Methods
    def with_packer_detection(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable packer detection"""
        self._packer_kwargs["enabled"] = enabled
        return self

    def with_entropy_threshold(self, threshold: float) -> "ConfigBuilder":
        """Set entropy threshold for packer detection"""
        self._packer_kwargs["entropy_threshold"] = threshold
        return self

    def with_section_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable section analysis for packer detection"""
        self._packer_kwargs["section_analysis"] = enabled
        return self

    # Crypto Configuration Methods
    def with_crypto_detection(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable crypto constant detection"""
        self._crypto_kwargs["enabled"] = enabled
        return self

    def with_crypto_constants(self, detect: bool = True) -> "ConfigBuilder":
        """Enable or disable crypto constants detection"""
        self._crypto_kwargs["detect_constants"] = detect
        return self

    def with_base64_detection(self, detect: bool = True) -> "ConfigBuilder":
        """Enable or disable base64 string detection"""
        self._crypto_kwargs["detect_base64"] = detect
        return self

    # Strings Configuration Methods
    def with_string_min_length(self, min_length: int) -> "ConfigBuilder":
        """Set minimum string length for extraction"""
        self._strings_kwargs["min_length"] = min_length
        return self

    def with_string_max_length(self, max_length: int) -> "ConfigBuilder":
        """Set maximum string length for extraction"""
        self._strings_kwargs["max_length"] = max_length
        return self

    def with_unicode_extraction(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable unicode string extraction"""
        self._strings_kwargs["extract_unicode"] = enabled
        return self

    def with_ascii_extraction(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable ASCII string extraction"""
        self._strings_kwargs["extract_ascii"] = enabled
        return self

    # Output Configuration Methods
    def with_json_indent(self, indent: int) -> "ConfigBuilder":
        """Set JSON output indentation"""
        self._output_kwargs["json_indent"] = indent
        return self

    def with_csv_delimiter(self, delimiter: str) -> "ConfigBuilder":
        """Set CSV delimiter character"""
        self._output_kwargs["csv_delimiter"] = delimiter
        return self

    def with_progress_display(self, show: bool = True) -> "ConfigBuilder":
        """Enable or disable progress display"""
        self._output_kwargs["show_progress"] = show
        return self

    # VirusTotal Configuration Methods
    def with_virustotal(self, api_key: str, enabled: bool = True) -> "ConfigBuilder":
        """Configure VirusTotal integration"""
        self._virustotal_kwargs["api_key"] = api_key
        self._virustotal_kwargs["enabled"] = enabled
        return self

    def with_virustotal_timeout(self, timeout: int) -> "ConfigBuilder":
        """Set VirusTotal API timeout in seconds"""
        self._virustotal_kwargs["timeout"] = timeout
        return self

    # Analysis Configuration Methods
    def with_deep_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable deep analysis"""
        self._analysis_kwargs["deep_analysis"] = enabled
        return self

    def with_function_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable function analysis"""
        self._analysis_kwargs["function_analysis"] = enabled
        return self

    def with_graph_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable graph analysis"""
        self._analysis_kwargs["graph_analysis"] = enabled
        return self

    # PE Analysis Configuration Methods
    def with_authenticode_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable Authenticode signature analysis"""
        self._pe_analysis_kwargs["analyze_authenticode"] = enabled
        return self

    def with_overlay_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable overlay analysis"""
        self._pe_analysis_kwargs["analyze_overlay"] = enabled
        return self

    def with_resource_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable resource analysis"""
        self._pe_analysis_kwargs["analyze_resources"] = enabled
        return self

    def with_mitigation_analysis(self, enabled: bool = True) -> "ConfigBuilder":
        """Enable or disable exploit mitigation analysis"""
        self._pe_analysis_kwargs["analyze_mitigations"] = enabled
        return self

    # Build Method
    def build(self) -> R2InspectConfig:
        """
        Build and return the R2InspectConfig instance.

        Returns:
            R2InspectConfig: Immutable configuration object

        Raises:
            ValueError: If configuration validation fails
        """
        return R2InspectConfig(
            general=(
                GeneralConfig(**self._general_kwargs) if self._general_kwargs else GeneralConfig()
            ),
            yara=YaraConfig(**self._yara_kwargs) if self._yara_kwargs else YaraConfig(),
            packer=PackerConfig(**self._packer_kwargs) if self._packer_kwargs else PackerConfig(),
            crypto=CryptoConfig(**self._crypto_kwargs) if self._crypto_kwargs else CryptoConfig(),
            strings=(
                StringsConfig(**self._strings_kwargs) if self._strings_kwargs else StringsConfig()
            ),
            output=OutputConfig(**self._output_kwargs) if self._output_kwargs else OutputConfig(),
            virustotal=(
                VirusTotalConfig(**self._virustotal_kwargs)
                if self._virustotal_kwargs
                else VirusTotalConfig()
            ),
            analysis=(
                AnalysisConfig(**self._analysis_kwargs)
                if self._analysis_kwargs
                else AnalysisConfig()
            ),
            pe_analysis=(
                PEAnalysisConfig(**self._pe_analysis_kwargs)
                if self._pe_analysis_kwargs
                else PEAnalysisConfig()
            ),
        )


def create_default_config() -> R2InspectConfig:
    """Create a default configuration instance"""
    return ConfigBuilder().build()


def create_verbose_config() -> R2InspectConfig:
    """Create a configuration with verbose output enabled"""
    return ConfigBuilder().with_verbose(True).build()


def create_minimal_config() -> R2InspectConfig:
    """Create a minimal configuration for basic analysis"""
    return (
        ConfigBuilder()
        .with_packer_detection(False)
        .with_crypto_detection(False)
        .with_yara_enabled(False)
        .with_function_analysis(False)
        .build()
    )


def create_full_analysis_config() -> R2InspectConfig:
    """Create a configuration for comprehensive analysis"""
    return (
        ConfigBuilder()
        .with_verbose(True)
        .with_deep_analysis(True)
        .with_function_analysis(True)
        .with_graph_analysis(True)
        .with_packer_detection(True)
        .with_crypto_detection(True)
        .with_yara_enabled(True)
        .build()
    )
