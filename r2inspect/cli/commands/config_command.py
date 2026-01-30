#!/usr/bin/env python3
"""
r2inspect CLI Commands - Config Command

Configuration management command implementation.

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

from pathlib import Path
from typing import Any

from rich.table import Table

from .base import Command


class ConfigCommand(Command):
    """
    Command for configuration management.

    Provides functionality to list available YARA rules and display
    configuration information. This command supports the --list-yara
    flag for discovering available YARA rule files.

    Responsibilities:
    - List available YARA rules from configured directories
    - Display YARA rule metadata (if available)
    - Show configuration file locations
    - Validate YARA rule accessibility

    Note: Currently focused on YARA rule listing. Can be extended
    for general configuration management (display config, validate, etc.)
    """

    def execute(self, args: dict[str, Any]) -> int:
        """
        Execute configuration command.

        Args:
            args: Dictionary containing:
                - list_yara: Flag to list available YARA rules
                - config: Optional config file path
                - yara: Optional custom YARA rules directory

        Returns:
            0 on success, 1 on failure
        """
        if args.get("list_yara", False):
            return self._list_yara_rules(
                config_path=args.get("config"),
                yara_path=args.get("yara"),
            )

        # Future: Add other config management operations
        self.context.console.print("[yellow]No configuration operation specified[/yellow]")
        return 0

    def _list_yara_rules(
        self,
        config_path: str | None = None,
        yara_path: str | None = None,
    ) -> int:
        """
        List all available YARA rules.

        Discovers and displays YARA rules from the configured directory
        or custom path. Shows rule files in a formatted table.

        Args:
            config_path: Optional config file path
            yara_path: Optional custom YARA rules directory

        Returns:
            0 on success, 1 on failure
        """
        config = self._get_config(config_path)

        # Determine YARA rules directory
        rules_path = Path(yara_path) if yara_path else Path(config.get_yara_rules_path())

        if not rules_path.exists():
            self.context.console.print(f"[red]YARA rules directory not found: {rules_path}[/red]")
            return 1

        # Find all YARA rule files
        available_rules = self._find_yara_rules(rules_path)

        if not available_rules:
            self.context.console.print(f"[yellow]No YARA rules found in: {rules_path}[/yellow]")
            return 0

        # Display rules in formatted table
        self._display_yara_rules_table(available_rules, rules_path)
        return 0

    def _find_yara_rules(self, rules_path: Path) -> list[Path]:
        """
        Find all YARA rule files in directory.

        Searches for .yar and .yara files recursively.

        Args:
            rules_path: Path to YARA rules directory

        Returns:
            List of YARA rule file paths
        """
        available_rules: list[Path] = []

        for pattern in ["*.yar", "*.yara"]:
            available_rules.extend(rules_path.rglob(pattern))

        return sorted(available_rules)

    def _display_yara_rules_table(
        self,
        available_rules: list[Path],
        rules_path: Path,
    ) -> None:
        """
        Display YARA rules in formatted table.

        Args:
            available_rules: List of YARA rule file paths
            rules_path: Base YARA rules directory path
        """
        table = Table(title=f"Available YARA Rules ({len(available_rules)} total)")
        table.add_column("Rule File", style="cyan")
        table.add_column("Size", style="green")
        table.add_column("Category", style="yellow")

        for rule_file in available_rules:
            # Get file size
            file_size = rule_file.stat().st_size
            size_str = self._format_file_size(file_size)

            # Determine category from parent directory
            category = rule_file.parent.name if rule_file.parent != rules_path else "Root"

            # Get relative path for display
            try:
                display_name = str(rule_file.relative_to(rules_path))
            except ValueError:
                display_name = rule_file.name

            table.add_row(display_name, size_str, category)

        self.context.console.print(table)
        self.context.console.print(f"\n[dim]Rules directory: {rules_path}[/dim]")

    def _format_file_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format.

        Args:
            size_bytes: File size in bytes

        Returns:
            Formatted size string (e.g., "1.5 KB")
        """
        size_value = float(size_bytes)
        for unit in ["B", "KB", "MB"]:
            if size_value < 1024.0:
                return f"{size_value:.1f} {unit}"
            size_value /= 1024.0
        return f"{size_value:.1f} GB"
