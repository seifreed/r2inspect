#!/usr/bin/env python3
"""
r2inspect Configuration Package
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

from .builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)
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

__all__ = [
    # Schema classes
    "R2InspectConfig",
    "GeneralConfig",
    "YaraConfig",
    "PackerConfig",
    "CryptoConfig",
    "StringsConfig",
    "OutputConfig",
    "VirusTotalConfig",
    "AnalysisConfig",
    "PEAnalysisConfig",
    # Builder classes and helpers
    "ConfigBuilder",
    "create_default_config",
    "create_verbose_config",
    "create_minimal_config",
    "create_full_analysis_config",
]
