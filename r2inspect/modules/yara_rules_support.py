"""Helpers for YARA rule IO, compilation and listing."""

from __future__ import annotations

import os
import signal
import threading
from pathlib import Path
from typing import Any


def discover_rule_files(rules_dir: Path, yara_extensions: list[str]) -> list[Path]:
    rules_found: list[Path] = []
    for extension in yara_extensions:
        rules_found.extend(rules_dir.glob(extension))
    for extension in yara_extensions:
        for rule_file in rules_dir.rglob(extension):
            if rule_file not in rules_found:
                rules_found.append(rule_file)
    return rules_found


def compile_sources_with_timeout(
    yara_module: Any,
    rules_dict: dict[str, str],
    timeout_seconds: int,
    timeout_handler: Any,
    logger: Any,
) -> Any | None:
    try:
        if hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread():
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_seconds)
            try:
                compiled_rules = yara_module.compile(sources=rules_dict)
                signal.alarm(0)
                return compiled_rules
            finally:
                signal.signal(signal.SIGALRM, old_handler)
        logger.debug("YARA compilation timeout not available on this platform")
        return yara_module.compile(sources=rules_dict)
    except yara_module.SyntaxError as exc:
        logger.error("YARA syntax error: %s", exc)
        return None
    except Exception as exc:
        logger.error("YARA compilation error: %s", exc)
        return None


def process_matches(yara_matches: list[Any], logger: Any) -> list[dict[str, Any]]:
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
            for string_match in match.strings:
                string_info = {"identifier": string_match.identifier, "instances": []}
                for instance in string_match.instances:
                    matched_data = instance.matched_data.decode("utf-8", errors="ignore")
                    length = getattr(instance, "length", len(instance.matched_data))
                    string_info["instances"].append(
                        {"offset": instance.offset, "matched_data": matched_data, "length": length}
                    )
                match_info["strings"].append(string_info)
            matches.append(match_info)
    except Exception as exc:
        logger.error("Error processing YARA matches: %s", exc)
    return matches


def list_available_rules(
    rules_path: str, yara_extensions: list[str], logger: Any
) -> list[dict[str, Any]]:
    available_rules: list[dict[str, Any]] = []
    try:
        if not os.path.exists(rules_path):
            logger.warning("YARA rules path not found: %s", rules_path)
            return available_rules
        if os.path.isfile(rules_path):
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
            return available_rules
        if os.path.isdir(rules_path):
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
                    except Exception as exc:
                        logger.warning("Error reading file info for %s: %s", rule_file, exc)
                        continue
        logger.info("Found %s YARA rule files total", len(available_rules))
    except Exception as exc:
        logger.error("Error listing YARA rules: %s", exc)
    return available_rules
