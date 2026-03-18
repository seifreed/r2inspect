#!/usr/bin/env python3
"""Configuration management command."""

from pathlib import Path
from typing import Any

from rich.table import Table

from .base import Command


class ConfigCommand(Command):
    """Configuration management command."""

    def execute(self, args: dict[str, Any]) -> int:
        """Execute configuration command."""
        if args.get("list_yara", False):
            return self._list_yara_rules(
                config_path=args.get("config"),
                yara_path=args.get("yara"),
            )

        self.context.console.print("[yellow]No configuration operation specified[/yellow]")
        return 0

    def _list_yara_rules(
        self,
        config_path: str | None = None,
        yara_path: str | None = None,
    ) -> int:
        config = self._get_config(config_path)
        rules_path = Path(yara_path) if yara_path else Path(config.get_yara_rules_path())

        if not rules_path.exists():
            self.context.console.print(f"[red]YARA rules directory not found: {rules_path}[/red]")
            return 1

        available_rules = self._find_yara_rules(rules_path)

        if not available_rules:
            self.context.console.print(f"[yellow]No YARA rules found in: {rules_path}[/yellow]")
            return 0

        self._display_yara_rules_table(available_rules, rules_path)
        return 0

    def _find_yara_rules(self, rules_path: Path) -> list[Path]:
        available_rules: list[Path] = []
        for pattern in ["*.yar", "*.yara"]:
            available_rules.extend(rules_path.rglob(pattern))
        return sorted(available_rules)

    def _display_yara_rules_table(
        self,
        available_rules: list[Path],
        rules_path: Path,
    ) -> None:
        table = Table(title=f"Available YARA Rules ({len(available_rules)} total)")
        table.add_column("Rule File", style="cyan")
        table.add_column("Size", style="green")
        table.add_column("Category", style="yellow")

        for rule_file in available_rules:
            size_str = self._format_file_size(rule_file.stat().st_size)
            category = rule_file.parent.name if rule_file.parent != rules_path else "Root"
            try:
                display_name = str(rule_file.relative_to(rules_path))
            except ValueError:
                display_name = rule_file.name
            table.add_row(display_name, size_str, category)

        self.context.console.print(table)
        self.context.console.print(f"\n[dim]Rules directory: {rules_path}[/dim]")

    def _format_file_size(self, size_bytes: int) -> str:
        size_value = float(size_bytes)
        for unit in ["B", "KB", "MB"]:
            if size_value < 1024.0:
                return f"{size_value:.1f} {unit}"
            size_value /= 1024.0
        return f"{size_value:.1f} GB"
