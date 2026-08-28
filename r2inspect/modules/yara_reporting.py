"""Validation and listing helpers for YARA rule collections."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol

from .yara_rules_support import YARA_RULE_PATTERNS, list_available_rules


class YaraRuleHost(Protocol):
    def _compile_rules(self, rules_path: str) -> Any | None: ...
    def _discover_rule_files(self, rules_dir: Path) -> list[Path]: ...


def validate_rules(analyzer: YaraRuleHost, rules_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": True, "errors": [], "warnings": [], "rules_count": 0}
    errors = result["errors"]
    try:
        rules = analyzer._compile_rules(rules_path)
        if rules:
            result["rules_count"] = (
                len(analyzer._discover_rule_files(Path(rules_path)))
                if os.path.isdir(rules_path)
                else 1
            )
        else:
            result["valid"] = False
            errors.append("Failed to compile rules")
    except Exception as exc:
        result["valid"] = False
        errors.append(str(exc))
    return result


def available_rules(rules_path: str, logger: Any) -> list[dict[str, Any]]:
    return list_available_rules(rules_path, list(YARA_RULE_PATTERNS), logger)
