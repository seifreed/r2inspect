#!/usr/bin/env python3
"""
r2inspect Configuration Management
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for r2inspect"""

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
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_path = config_path or self._get_default_config_path()

        # Load configuration if exists
        if os.path.exists(self.config_path):
            self.load_config()
        else:
            self.save_config()  # Create default config

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        config_dir = home_dir / ".r2inspect"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "config.json")

    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_path, "r") as f:
                user_config = json.load(f)
                self._merge_config(user_config)
        except Exception as e:
            print(f"Warning: Could not load config from {self.config_path}: {e}")

    def save_config(self):
        """Save configuration to file"""
        try:
            config_dir = Path(self.config_path).parent
            config_dir.mkdir(exist_ok=True)

            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config to {self.config_path}: {e}")

    def _merge_config(self, user_config: Dict[str, Any]):
        """Merge user configuration with defaults"""
        for section, settings in user_config.items():
            if section in self.config:
                if isinstance(settings, dict):
                    self.config[section].update(settings)
                else:
                    self.config[section] = settings
            else:
                self.config[section] = settings

    def get(self, section: str, key: str = None, default=None):
        """Get configuration value"""
        if key is None:
            return self.config.get(section, default)
        return self.config.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

    def get_yara_rules_path(self) -> str:
        """Get YARA rules directory path"""
        rules_path = self.get("yara", "rules_path")
        if not os.path.isabs(rules_path):
            # Relative to r2inspect package
            package_dir = Path(__file__).parent
            rules_path = package_dir / rules_path
        return str(rules_path)

    def is_virustotal_enabled(self) -> bool:
        """Check if VirusTotal integration is enabled"""
        return self.get("virustotal", "enabled") and self.get("virustotal", "api_key")

    def get_virustotal_api_key(self) -> str:
        """Get VirusTotal API key"""
        return self.get("virustotal", "api_key", "")

    def __getitem__(self, key):
        """Allow dict-like access"""
        return self.config[key]

    def __contains__(self, key):
        """Allow 'in' operator"""
        return key in self.config
