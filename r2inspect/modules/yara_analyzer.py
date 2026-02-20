#!/usr/bin/env python3
"""YARA analysis module."""

from __future__ import annotations

import os
import signal
import threading
from pathlib import Path
from typing import Any

try:
    import yara
except Exception:  # pragma: no cover - optional dependency
    yara = None

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..adapters.file_system import default_file_system
from ..security.validators import FileValidator
from ..utils.logger import get_logger
from .yara_defaults import DEFAULT_YARA_RULES

logger = get_logger(__name__)

# Constants
YARA_EXT = "*.yar"
YARA_YARA_EXT = "*.yara"

# Security limits for YARA compilation
YARA_COMPILE_TIMEOUT = 30  # seconds
YARA_MAX_RULE_SIZE = 10 * 1024 * 1024  # 10MB per rule file


class TimeoutException(Exception):
    """Exception raised when YARA compilation times out."""

    pass


def timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for compilation timeout."""
    raise TimeoutException("YARA compilation timed out")


_COMPILED_CACHE: dict[str, Any] = {}


class YaraAnalyzer(CommandHelperMixin):
    """YARA rules analysis"""

    def __init__(
        self,
        adapter: Any,
        config: Any | None = None,
        filepath: str | None = None,
    ) -> None:
        self.adapter = adapter
        self.r2 = adapter
        if config is None:
            raise ValueError("config must be provided")
        self.config = config
        self.rules_path = str(config.get_yara_rules_path())
        self.filepath = filepath  # Store filepath directly to avoid r2 dependency

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
            logger.error(f"Error in YARA scan: {e}")

        return matches

    def _resolve_file_path(self) -> str | None:
        file_path = self.filepath
        if not file_path:
            file_info = self._cmdj("ij", {})
            if file_info and "core" in file_info:
                file_path = str(file_info["core"].get("file", ""))
        if not file_path or not os.path.exists(file_path):
            logger.debug(f"File not accessible for YARA scan: {file_path}")
            return None
        return file_path

    def _resolve_rules_path(self, custom_rules_path: str | None) -> str | None:
        rules_path = custom_rules_path or self.rules_path or ""
        if os.path.exists(rules_path):
            return rules_path
        logger.info(f"YARA rules path not found: {rules_path}. Creating defaults.")
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
        """
        Compile YARA rules from directory or file with security validation.

        Security: Prevents YARA rule injection and DoS attacks (CWE-400, CWE-94) by:
        1. Validating file paths to prevent directory traversal
        2. Enforcing size limits on rule files
        3. Validating rule content for dangerous patterns
        4. Implementing compilation timeout to prevent DoS
        5. Using signal-based timeout (Unix/Linux) or basic timeout (Windows)

        Args:
            rules_path: Path to YARA rules file or directory

        Returns:
            Compiled YARA rules or None if compilation fails
        """
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

            logger.debug(f"Successfully loaded {len(rules_dict)} YARA rule source(s)")
            return self._compile_sources_with_timeout(rules_dict)
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            return None

    def _validate_rules_path(self, validator: FileValidator, rules_path: str) -> Path | None:
        try:
            return validator.validate_path(rules_path, check_exists=True)
        except ValueError as e:
            logger.error(f"YARA rules path validation failed: {e}")
            return None

    def _collect_rules_sources(
        self, validator: FileValidator, validated_path: Path
    ) -> dict[str, str]:
        if validated_path.is_file():
            return self._load_single_rule(validator, validated_path)
        if validated_path.is_dir():
            return self._load_rules_dir(validator, validated_path)
        logger.error(f"YARA rules path is neither file nor directory: {validated_path}")
        return {}

    def _load_single_rule(self, validator: FileValidator, rule_path: Path) -> dict[str, str]:
        logger.debug(f"Loading single YARA file: {rule_path}")
        content = self._read_rule_content(validator, rule_path)
        return {"single_rule": content} if content else {}

    def _load_rules_dir(self, validator: FileValidator, rules_dir: Path) -> dict[str, str]:
        rules_dict: dict[str, str] = {}
        rules_found = self._discover_rule_files(rules_dir)
        logger.debug(f"Found {len(rules_found)} YARA rule files in {rules_dir}")

        for rule_file in rules_found:
            content = self._read_rule_content(validator, rule_file)
            if not content:
                continue
            relative_path = rule_file.relative_to(rules_dir)
            rules_dict[str(relative_path)] = content

        return rules_dict

    def _discover_rule_files(self, rules_dir: Path) -> list[Path]:
        yara_extensions = [YARA_EXT, YARA_YARA_EXT, "*.rule", "*.rules"]
        rules_found: list[Path] = []

        for extension in yara_extensions:
            rules_found.extend(rules_dir.glob(extension))

        for extension in yara_extensions:
            for rule_file in rules_dir.rglob(extension):
                if rule_file not in rules_found:
                    rules_found.append(rule_file)

        return rules_found

    def _read_rule_content(self, validator: FileValidator, rule_file: Path) -> str | None:
        try:
            logger.debug(f"Loading YARA file: {rule_file.name}")
            try:
                validated_rule = validator.validate_path(str(rule_file), check_exists=True)
            except ValueError as e:
                logger.info(f"Skipping YARA rule (path invalid) {rule_file}: {e}")
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
                logger.info(f"Skipping empty YARA file: {rule_file}")
                return None

            try:
                validator.validate_yara_rule_content(content, YARA_MAX_RULE_SIZE)
            except ValueError as e:
                logger.debug(f"Skipping YARA rule due to validation {rule_file}: {e}")
                return None

            return content
        except Exception as e:
            logger.warning(f"Failed to read YARA file {rule_file}: {e}")
            return None

    def _compile_default_rules(self, rules_path: str) -> yara.Rules | None:
        logger.info(f"No valid YARA rules found in: {rules_path}. Using defaults.")
        self.create_default_rules()
        try:
            return yara.compile(
                sources={"default": (Path(self.rules_path) / "packer_detection.yar").read_text()}
            )
        except Exception:
            return None

    def _compile_sources_with_timeout(self, rules_dict: dict[str, str]) -> yara.Rules | None:
        try:
            if hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread():
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(YARA_COMPILE_TIMEOUT)
                try:
                    compiled_rules = yara.compile(sources=rules_dict)
                    signal.alarm(0)
                    return compiled_rules
                except TimeoutException:  # pragma: no cover
                    logger.error(
                        f"YARA compilation timed out after {YARA_COMPILE_TIMEOUT}s"
                    )  # pragma: no cover
                    return None  # pragma: no cover
                finally:
                    signal.signal(signal.SIGALRM, old_handler)
            else:
                logger.debug("YARA compilation timeout not available on this platform")
                return yara.compile(sources=rules_dict)
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
            return None
        except Exception as e:
            logger.error(f"YARA compilation error: {e}")
            return None

    def _process_matches(self, yara_matches: list[Any]) -> list[dict[str, Any]]:
        """Process YARA matches into structured format"""
        matches: list[dict[str, Any]] = []

        try:
            for match in yara_matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": [],
                }

                # Process string matches
                for string_match in match.strings:
                    string_info = {
                        "identifier": string_match.identifier,
                        "instances": [],
                    }

                    for instance in string_match.instances:
                        instance_info = {
                            "offset": instance.offset,
                            "matched_data": instance.matched_data.decode("utf-8", errors="ignore"),
                        }

                        # Handle different YARA versions - some have length attribute, some don't
                        if hasattr(instance, "length"):  # pragma: no cover
                            instance_info["length"] = instance.length  # pragma: no cover
                        else:  # pragma: no cover
                            instance_info["length"] = len(instance.matched_data)

                        string_info["instances"].append(instance_info)

                    match_info["strings"].append(string_info)

                matches.append(match_info)

        except Exception as e:
            logger.error(f"Error processing YARA matches: {e}")

        return matches

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
            logger.error(f"Error creating default rules: {e}")

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
                validation_result["valid"] = True
                # Count rules (this is a simplified count)
                if os.path.isdir(rules_path):
                    yar_files = list(Path(rules_path).glob(YARA_EXT))
                    yara_files = list(Path(rules_path).glob(YARA_YARA_EXT))
                    validation_result["rules_count"] = len(yar_files) + len(yara_files)
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
        available_rules: list[dict[str, Any]] = []

        try:
            if not os.path.exists(rules_path):
                logger.warning(f"YARA rules path not found: {rules_path}")
                return available_rules

            if os.path.isfile(rules_path):
                # Single file
                stat = os.stat(rules_path)
                available_rules.append(
                    {
                        "name": Path(rules_path).name,
                        "path": rules_path,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                        "type": "single_file",
                    }
                )
            elif os.path.isdir(rules_path):
                # Directory
                yara_extensions = [YARA_EXT, YARA_YARA_EXT, "*.rule", "*.rules"]

                for extension in yara_extensions:
                    for rule_file in Path(rules_path).rglob(extension):
                        try:
                            stat = rule_file.stat()
                            relative_path = rule_file.relative_to(Path(rules_path))

                            available_rules.append(
                                {
                                    "name": rule_file.name,
                                    "path": str(rule_file),
                                    "relative_path": str(relative_path),
                                    "size": stat.st_size,
                                    "modified": stat.st_mtime,
                                    "type": "directory_file",
                                }
                            )
                        except Exception as e:
                            logger.warning(f"Error reading file info for {rule_file}: {e}")
                            continue

            logger.info(f"Found {len(available_rules)} YARA rule files total")

        except Exception as e:
            logger.error(f"Error listing YARA rules: {e}")

        return available_rules
