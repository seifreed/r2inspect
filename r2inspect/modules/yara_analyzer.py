#!/usr/bin/env python3
"""YARA analysis module."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yara
except Exception:  # pragma: no cover - optional dependency
    yara = None

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..adapters.file_system import default_file_system
from ..security.validators import FileValidator
from ..infrastructure.logging import get_logger
from .yara_rules_support import (
    compile_sources_with_timeout,
    discover_rule_files,
    list_available_rules as collect_available_rules,
    process_matches,
)
from .yara_defaults import DEFAULT_YARA_RULES

logger = get_logger(__name__)

YARA_EXT = "*.yar"
YARA_YARA_EXT = "*.yara"
YARA_COMPILE_TIMEOUT = 30  # seconds
YARA_MAX_RULE_SIZE = 10 * 1024 * 1024  # 10MB per rule file


class TimeoutException(Exception):
    """Exception raised when YARA compilation times out."""

    pass


def timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for compilation timeout."""
    raise TimeoutException("YARA compilation timed out")


_COMPILED_CACHE: dict[str, Any] = {}


def clear_yara_cache() -> None:
    """Clear the compiled YARA rules cache (useful for test isolation)."""
    _COMPILED_CACHE.clear()


class YaraAnalyzer(CommandHelperMixin):
    """YARA rules analysis"""

    def __init__(
        self,
        adapter: Any,
        config: Any | None = None,
        filepath: str | None = None,
    ) -> None:
        self.adapter = adapter
        if config is None:
            raise ValueError("config must be provided")
        self.config = config
        self.rules_path = str(config.get_yara_rules_path())
        self.filepath = filepath  # Store filepath directly to avoid r2 dependency

    def analyze(self, custom_rules_path: str | None = None) -> list[dict[str, Any]]:
        """Unified entry point for pipeline dispatch."""
        return self.scan(custom_rules_path)

    def scan(self, custom_rules_path: str | None = None) -> list[dict[str, Any]]:
        """Scan file with YARA rules"""
        matches: list[dict[str, Any]] = []

        try:
            if yara is None:
                logger.warning("python-yara not available; skipping YARA scan")
                return matches
            file_path = self._resolve_file_path()
            if not file_path:
                return matches

            rules_path = self._resolve_rules_path(custom_rules_path)
            if not rules_path:
                return matches

            rules = self._get_cached_rules(rules_path)
            if not rules:
                return matches

            yara_matches = rules.match(file_path)
            matches = self._process_matches(yara_matches)

        except Exception as e:
            logger.error("Error in YARA scan: %s", e)

        return matches

    def _resolve_file_path(self) -> str | None:
        file_path = self.filepath
        if not file_path:
            file_info = self._cmdj("ij", {})
            if file_info and "core" in file_info:
                file_path = str(file_info["core"].get("file", ""))
        if not file_path or not os.path.exists(file_path):
            logger.debug("File not accessible for YARA scan: %s", file_path)
            return None
        return file_path

    def _resolve_rules_path(self, custom_rules_path: str | None) -> str | None:
        rules_path = custom_rules_path or self.rules_path or ""
        if os.path.exists(rules_path):
            return rules_path
        logger.info("YARA rules path not found: %s. Creating defaults.", rules_path)
        self.create_default_rules()
        return rules_path if os.path.exists(rules_path) else None

    def _get_cached_rules(self, rules_path: str) -> Any | None:
        rules = _COMPILED_CACHE.get(rules_path)
        if rules:
            return rules
        rules = self._compile_rules(rules_path)
        if rules:
            _COMPILED_CACHE[rules_path] = rules
        return rules

    def _compile_rules(self, rules_path: str) -> Any | None:
        """Compile YARA rules from a validated file or directory."""
        try:
            if yara is None:
                logger.warning("python-yara not available; skipping rules compilation")
                return None
            validator = FileValidator()
            validated_path = self._validate_rules_path(validator, rules_path)
            if not validated_path:
                return None
            rules_dict = self._collect_rules_sources(validator, validated_path)
            if not rules_dict:
                return self._compile_default_rules(rules_path)
            logger.debug("Successfully loaded %s YARA rule source(s)", len(rules_dict))
            return self._compile_sources_with_timeout(rules_dict)
        except Exception as e:
            logger.error("Error compiling YARA rules: %s", e)
            return None

    def _validate_rules_path(self, validator: FileValidator, rules_path: str) -> Path | None:
        try:
            return validator.validate_path(rules_path, check_exists=True)
        except ValueError as e:
            logger.error("YARA rules path validation failed: %s", e)
            return None

    def _collect_rules_sources(
        self, validator: FileValidator, validated_path: Path
    ) -> dict[str, str]:
        if validated_path.is_file():
            return self._load_single_rule(validator, validated_path)
        if validated_path.is_dir():
            return self._load_rules_dir(validator, validated_path)
        logger.error("YARA rules path is neither file nor directory: %s", validated_path)
        return {}

    def _load_single_rule(self, validator: FileValidator, rule_path: Path) -> dict[str, str]:
        logger.debug("Loading single YARA file: %s", rule_path)
        content = self._read_rule_content(validator, rule_path)
        return {"single_rule": content} if content else {}

    def _load_rules_dir(self, validator: FileValidator, rules_dir: Path) -> dict[str, str]:
        rules_dict: dict[str, str] = {}
        rules_found = self._discover_rule_files(rules_dir)
        logger.debug("Found %s YARA rule files in %s", len(rules_found), rules_dir)

        for rule_file in rules_found:
            content = self._read_rule_content(validator, rule_file)
            if not content:
                continue
            relative_path = rule_file.relative_to(rules_dir)
            rules_dict[str(relative_path)] = content

        return rules_dict

    def _discover_rule_files(self, rules_dir: Path) -> list[Path]:
        return discover_rule_files(rules_dir, [YARA_EXT, YARA_YARA_EXT, "*.rule", "*.rules"])

    def _read_rule_content(self, validator: FileValidator, rule_file: Path) -> str | None:
        try:
            logger.debug("Loading YARA file: %s", rule_file.name)
            try:
                validated_rule = validator.validate_path(str(rule_file), check_exists=True)
            except ValueError as e:
                logger.info("Skipping YARA rule (path invalid) %s: %s", rule_file, e)
                return None
            file_size = validated_rule.stat().st_size
            if file_size > YARA_MAX_RULE_SIZE:
                logger.info(
                    f"YARA rule file too large, skipping: {rule_file} "
                    f"({file_size} > {YARA_MAX_RULE_SIZE})"
                )
                return None
            content = default_file_system.read_text(
                validated_rule,
                encoding="utf-8",
                errors="ignore",
            ).strip()
            if not content:
                logger.info("Skipping empty YARA file: %s", rule_file)
                return None
            try:
                validator.validate_yara_rule_content(content, YARA_MAX_RULE_SIZE)
            except ValueError as e:
                logger.debug("Skipping YARA rule due to validation %s: %s", rule_file, e)
                return None

            return content
        except Exception as e:
            logger.warning("Failed to read YARA file %s: %s", rule_file, e)
            return None

    def _compile_default_rules(self, rules_path: str) -> yara.Rules | None:
        logger.info("No valid YARA rules found in: %s. Using defaults.", rules_path)
        self.create_default_rules()
        try:
            return yara.compile(
                sources={"default": (Path(rules_path) / "packer_detection.yar").read_text()}
            )
        except Exception as exc:
            logger.error("Failed to compile default YARA rules: %s", exc)
            return None

    def _compile_sources_with_timeout(self, rules_dict: dict[str, str]) -> yara.Rules | None:
        return compile_sources_with_timeout(
            yara,
            rules_dict,
            YARA_COMPILE_TIMEOUT,
            timeout_handler,
            logger,
        )

    def _process_matches(self, yara_matches: list[Any]) -> list[dict[str, Any]]:
        """Process YARA matches into structured format"""
        return process_matches(yara_matches, logger)

    def create_default_rules(self) -> None:
        """Create default YARA rules if none exist"""
        try:
            rules_dir = Path(self.rules_path)
            rules_dir.mkdir(parents=True, exist_ok=True)
            for filename, content in DEFAULT_YARA_RULES.items():
                rule_file = rules_dir / filename
                if not rule_file.exists():
                    default_file_system.write_text(rule_file, content)
        except Exception as e:
            logger.error("Error creating default rules: %s", e)

    def validate_rules(self, rules_path: str) -> dict[str, Any]:
        """Validate YARA rules syntax"""
        validation_result: dict[str, Any] = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "rules_count": 0,
        }

        try:
            rules = self._compile_rules(rules_path)
            if rules:
                if os.path.isdir(rules_path):
                    yar_files = list(Path(rules_path).glob(YARA_EXT))
                    yara_ext_files = list(Path(rules_path).glob(YARA_YARA_EXT))
                    validation_result["rules_count"] = len(yar_files) + len(yara_ext_files)
                else:
                    validation_result["rules_count"] = 1
            else:
                validation_result["valid"] = False
                validation_result["errors"].append("Failed to compile rules")
        except Exception as e:
            validation_result["valid"] = False
            validation_result["errors"].append(str(e))

        return validation_result

    def list_available_rules(self, rules_path: str | None = None) -> list[dict[str, Any]]:
        """List all available YARA rules in the rules directory"""
        rules_path = rules_path or self.rules_path
        return collect_available_rules(
            rules_path,
            [YARA_EXT, YARA_YARA_EXT, "*.rule", "*.rules"],
            logger,
        )
