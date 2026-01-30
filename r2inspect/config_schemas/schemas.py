#!/usr/bin/env python3
"""
r2inspect Configuration Schemas - Typed Dataclasses
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

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class GeneralConfig:
    """General configuration settings"""

    verbose: bool = False
    max_strings: int = 1000
    min_string_length: int = 4
    max_string_length: int = 100

    def __post_init__(self):
        """Validate configuration values"""
        if self.max_strings < 0:
            raise ValueError("max_strings must be non-negative")
        if self.min_string_length < 1:
            raise ValueError("min_string_length must be at least 1")
        if self.max_string_length < self.min_string_length:
            raise ValueError("max_string_length must be >= min_string_length")


@dataclass(frozen=True)
class YaraConfig:
    """YARA rules configuration"""

    rules_path: str = "rules/yara"
    enabled: bool = True
    timeout: int = 60

    def __post_init__(self):
        """Validate configuration values"""
        if self.timeout < 1:
            raise ValueError("timeout must be at least 1 second")


@dataclass(frozen=True)
class PackerConfig:
    """Packer detection configuration"""

    enabled: bool = True
    entropy_threshold: float = 7.0
    section_analysis: bool = True

    def __post_init__(self):
        """Validate configuration values"""
        if not (0.0 <= self.entropy_threshold <= 8.0):
            raise ValueError("entropy_threshold must be between 0.0 and 8.0")


@dataclass(frozen=True)
class CryptoConfig:
    """Cryptographic detection configuration"""

    enabled: bool = True
    detect_constants: bool = True
    detect_base64: bool = True


@dataclass(frozen=True)
class StringsConfig:
    """String extraction configuration"""

    min_length: int = 4
    max_length: int = 100
    extract_unicode: bool = True
    extract_ascii: bool = True

    def __post_init__(self):
        """Validate configuration values"""
        if self.min_length < 1:
            raise ValueError("min_length must be at least 1")
        if self.max_length < self.min_length:
            raise ValueError("max_length must be >= min_length")


@dataclass(frozen=True)
class OutputConfig:
    """Output formatting configuration"""

    json_indent: int = 2
    csv_delimiter: str = ","
    show_progress: bool = True

    def __post_init__(self):
        """Validate configuration values"""
        if self.json_indent < 0:
            raise ValueError("json_indent must be non-negative")
        if len(self.csv_delimiter) != 1:
            raise ValueError("csv_delimiter must be a single character")


@dataclass(frozen=True)
class VirusTotalConfig:
    """VirusTotal API configuration"""

    api_key: str = ""
    enabled: bool = False
    timeout: int = 30

    def __post_init__(self):
        """Validate configuration values"""
        if self.timeout < 1:
            raise ValueError("timeout must be at least 1 second")

    @property
    def is_configured(self) -> bool:
        """Check if VirusTotal is properly configured"""
        return self.enabled and bool(self.api_key)


@dataclass(frozen=True)
class AnalysisConfig:
    """Analysis options configuration"""

    deep_analysis: bool = False
    function_analysis: bool = True
    graph_analysis: bool = False


@dataclass(frozen=True)
class PEAnalysisConfig:
    """PE-specific analysis configuration"""

    analyze_authenticode: bool = True
    analyze_overlay: bool = True
    analyze_resources: bool = True
    analyze_mitigations: bool = True


@dataclass(frozen=True)
class R2InspectConfig:
    """Main r2inspect configuration container"""

    general: GeneralConfig = field(default_factory=GeneralConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    packer: PackerConfig = field(default_factory=PackerConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    strings: StringsConfig = field(default_factory=StringsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    pe_analysis: PEAnalysisConfig = field(default_factory=PEAnalysisConfig)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary"""
        result = {}
        for key, value in asdict(self).items():
            result[key] = value
        return result

    @classmethod
    def from_dict(cls, config_dict: dict[str, Any]) -> "R2InspectConfig":
        """Create configuration from dictionary"""
        if not isinstance(config_dict, dict):
            raise TypeError("config_dict must be a dictionary")

        kwargs: dict[str, Any] = {}

        # Parse general config
        if "general" in config_dict:
            kwargs["general"] = GeneralConfig(**config_dict["general"])

        # Parse yara config
        if "yara" in config_dict:
            kwargs["yara"] = YaraConfig(**config_dict["yara"])

        # Parse packer config
        if "packer" in config_dict:
            kwargs["packer"] = PackerConfig(**config_dict["packer"])

        # Parse crypto config
        if "crypto" in config_dict:
            kwargs["crypto"] = CryptoConfig(**config_dict["crypto"])

        # Parse strings config
        if "strings" in config_dict:
            kwargs["strings"] = StringsConfig(**config_dict["strings"])

        # Parse output config
        if "output" in config_dict:
            kwargs["output"] = OutputConfig(**config_dict["output"])

        # Parse virustotal config
        if "virustotal" in config_dict:
            kwargs["virustotal"] = VirusTotalConfig(**config_dict["virustotal"])

        # Parse analysis config
        if "analysis" in config_dict:
            kwargs["analysis"] = AnalysisConfig(**config_dict["analysis"])

        # Parse pe_analysis config
        if "pe_analysis" in config_dict:
            kwargs["pe_analysis"] = PEAnalysisConfig(**config_dict["pe_analysis"])

        return cls(**kwargs)

    def merge(self, other: "R2InspectConfig") -> "R2InspectConfig":
        """Merge with another configuration, with other taking precedence"""
        return R2InspectConfig.from_dict({**self.to_dict(), **other.to_dict()})
