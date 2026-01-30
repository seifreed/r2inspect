#!/usr/bin/env python3
"""
r2inspect CLI Commands - Version Command

Version display command implementation.

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

from typing import Any

from ...__version__ import __author__, __license__, __url__, __version__
from .base import Command


class VersionCommand(Command):
    """
    Command for displaying version information.

    Provides version, author, license, and repository information
    for the r2inspect tool. This is typically invoked via the --version
    flag but can be used programmatically as well.

    Responsibilities:
    - Display current version number
    - Show author and contact information
    - Display license information
    - Provide repository URL
    """

    def execute(self, _args: dict[str, Any]) -> int:
        """
        Execute version display command.

        Args:
            args: Dictionary (unused for version command)

        Returns:
            0 (always successful)
        """
        self._display_version_info()
        return 0

    def _display_version_info(self) -> None:
        """Display formatted version information."""
        self.context.console.print(
            f"[bold cyan]r2inspect[/bold cyan] version [bold green]{__version__}[/bold green]"
        )
        self.context.console.print(f"Author: {__author__}")
        self.context.console.print(f"License: {__license__}")
        self.context.console.print(f"Repository: {__url__}")
