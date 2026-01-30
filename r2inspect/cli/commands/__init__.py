#!/usr/bin/env python3
"""
r2inspect CLI Commands Package

Command Pattern implementation for r2inspect CLI.

This package provides modular, testable command implementations following
the Command Pattern design. Each command encapsulates a specific CLI
operation with clear separation of concerns.

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

from .analyze_command import AnalyzeCommand
from .base import Command, CommandContext
from .batch_command import BatchCommand
from .config_command import ConfigCommand
from .interactive_command import InteractiveCommand
from .version_command import VersionCommand

__all__ = [
    "Command",
    "CommandContext",
    "AnalyzeCommand",
    "BatchCommand",
    "InteractiveCommand",
    "VersionCommand",
    "ConfigCommand",
]
