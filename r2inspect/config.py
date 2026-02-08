#!/usr/bin/env python3
"""
r2inspect Configuration Management
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

import json
import os
from pathlib import Path
from typing import Any, cast

from .config_schemas.schemas import R2InspectConfig
from .config_store import ConfigStore


class Config:
    """
    Configuration manager for r2inspect.

    This class maintains a typed configuration for type safety and validation,
    while storing a full dictionary for persistence.
    """

    DEFAULT_CONFIG = {
        "general": {
            "verbose": False,
            "max_strings": 1000,
            "min_string_length": 4,
            "max_string_length": 100,
        },
        "yara": {"rules_path": "rules/yara", "enabled": True, "timeout": 60},
        "packer": {"enabled": True, "entropy_threshold": 7.0, "section_analysis": True},
        "crypto": {"enabled": True, "detect_constants": True, "detect_base64": True},
        "strings": {
            "extract_unicode": True,
            "extract_ascii": True,
            "min_length": 4,
            "max_length": 100,
        },
        "output": {"json_indent": 2, "csv_delimiter": ",", "show_progress": True},
        "virustotal": {"api_key": "", "enabled": False, "timeout": 30},
        "analysis": {
            "deep_analysis": False,
            "function_analysis": True,
            "graph_analysis": False,
        },
        "pe_analysis": {
            "analyze_authenticode": True,
            "analyze_overlay": True,
            "analyze_resources": True,
            "analyze_mitigations": True,
        },
        "pipeline": {
            "parallel_execution": True,
            "max_workers": 4,
            "stage_timeout": None,
        },
    }

    def __init__(self, config_path: str | None = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to configuration file. If None, uses default location.
        """
        self.config_path = config_path or self._get_default_config_path()

        # Initialize with default typed config and also keep a full dict copy
        self._typed_config = R2InspectConfig.from_dict(self.DEFAULT_CONFIG)
        self._full_config_dict: dict[str, Any] = json.loads(json.dumps(self.DEFAULT_CONFIG))

        # Load configuration if exists
        if os.path.exists(self.config_path):
            self.load_config()
        else:
            self.save_config()  # Create default config

    @property
    def typed_config(self) -> R2InspectConfig:
        """
        Get the typed configuration object.

        Returns:
            R2InspectConfig: Immutable typed configuration
        """
        return self._typed_config

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        config_dir = home_dir / ".r2inspect"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "config.json")

    def load_config(self) -> None:
        """Load configuration from file."""
        loaded = ConfigStore.load(self.config_path)
        if isinstance(loaded, dict):
            self._load_from_dict(loaded)

    @staticmethod
    def _merge_config(defaults: dict[str, Any], user_config: dict[str, Any]) -> dict[str, Any]:
        """Merge user configuration into defaults, preserving unknown sections."""
        merged_config = cast(dict[str, Any], json.loads(json.dumps(defaults)))
        for section, settings in user_config.items():
            if section in merged_config:
                if isinstance(settings, dict) and isinstance(merged_config[section], dict):
                    merged_config[section].update(settings)
                else:
                    merged_config[section] = settings
            else:
                merged_config[section] = settings
        return merged_config

    def _load_from_dict(self, user_config: dict[str, Any]) -> None:
        """
        Load configuration from dictionary.

        Args:
            user_config: User configuration dictionary
        """
        # Merge user config with defaults (preserve unknown sections)
        merged_config = self._merge_config(self.DEFAULT_CONFIG, user_config)

        # Store full merged configuration
        self._full_config_dict = merged_config

        # Create typed config from merged dictionary (unknown sections ignored by schema)
        try:
            self._typed_config = R2InspectConfig.from_dict(merged_config)
        except (ValueError, TypeError) as e:
            print(f"Warning: Invalid configuration values: {e}")
            print("Using default configuration")
            self._typed_config = R2InspectConfig.from_dict(self.DEFAULT_CONFIG)

    def save_config(self) -> None:
        """Save configuration to file."""
        ConfigStore.save(self.config_path, self.to_dict())

    def apply_overrides(self, overrides: dict[str, Any]) -> None:
        """
        Apply a set of configuration overrides.

        Args:
            overrides: Mapping of section -> settings to merge.
        """
        config_dict = self.to_dict()
        for section, settings in overrides.items():
            if isinstance(settings, dict) and isinstance(config_dict.get(section), dict):
                config_dict[section].update(settings)
            else:
                config_dict[section] = settings
        self._load_from_dict(config_dict)

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Set a single configuration value.

        Args:
            section: Top-level config section name
            key: Config key within the section
            value: Value to set
        """
        config_dict = self.to_dict()
        section_dict = config_dict.get(section)
        if not isinstance(section_dict, dict):
            section_dict = {}
        section_dict[key] = value
        config_dict[section] = section_dict
        self._load_from_dict(config_dict)

    def from_dict(self, config_dict: dict[str, Any]) -> "Config":
        """
        Create Config instance from dictionary.

        Args:
            config_dict: Configuration dictionary

        Returns:
            Config: New configuration instance
        """
        config_instance = Config.__new__(Config)
        config_instance.config_path = self.config_path
        config_instance._load_from_dict(config_dict)
        return config_instance

    def to_dict(self) -> dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            dict[str, Any]: Configuration dictionary
        """
        return dict(self._full_config_dict)

    def get_yara_rules_path(self) -> str:
        """Get YARA rules directory path"""
        rules_path = self.typed_config.yara.rules_path
        if not os.path.isabs(rules_path):
            # Relative to r2inspect package
            package_dir = Path(__file__).parent
            rules_path = str(package_dir / rules_path)
        return rules_path

    def is_virustotal_enabled(self) -> bool:
        """Check if VirusTotal integration is enabled"""
        return self.typed_config.virustotal.is_configured

    def get_virustotal_api_key(self) -> str:
        """Get VirusTotal API key"""
        return self.typed_config.virustotal.api_key

    # PE Analysis configuration properties
    @property
    def analyze_authenticode(self) -> bool:
        """Check if Authenticode analysis is enabled"""
        return self.typed_config.pe_analysis.analyze_authenticode

    @property
    def analyze_overlay(self) -> bool:
        """Check if overlay analysis is enabled"""
        return self.typed_config.pe_analysis.analyze_overlay

    @property
    def analyze_resources(self) -> bool:
        """Check if resource analysis is enabled"""
        return self.typed_config.pe_analysis.analyze_resources

    @property
    def analyze_mitigations(self) -> bool:
        """Check if exploit mitigation analysis is enabled"""
        return self.typed_config.pe_analysis.analyze_mitigations
