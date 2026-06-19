"""Helpers for YARA rule IO, compilation and listing."""

from __future__ import annotations

import os
import signal
import threading
from pathlib import Path
from typing import Any


def _coerce_extensions(yara_extensions: Any) -> list[str]:
    if isinstance(yara_extensions, list):
        return [ext for ext in yara_extensions if isinstance(ext, str) and ext]
    try:
        return [ext for ext in list(yara_extensions) if isinstance(ext, str) and ext]
    except TypeError:
        return []


def discover_rule_files(rules_dir: Path, yara_extensions: list[str]) -> list[Path]:
    rules_found: list[Path] = []
    for extension in _coerce_extensions(yara_extensions):
        rules_found.extend(rules_dir.glob(extension))
    for extension in _coerce_extensions(yara_extensions):
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
        if isinstance(yara_matches, list):
            match_source = yara_matches
        else:
            try:
                match_source = list(yara_matches)
            except TypeError:
                return matches
        for match in match_source:
            if not hasattr(match, "rule") or not hasattr(match, "strings"):
                continue
            tags = getattr(match, "tags", [])
            meta = getattr(match, "meta", {})
            strings = getattr(match, "strings", [])
            if not isinstance(strings, (list, tuple)):
                continue
            match_info = {
                "rule": str(getattr(match, "rule", "")),
                "namespace": str(getattr(match, "namespace", "")),
                "tags": list(tags) if isinstance(tags, (list, tuple, set)) else [],
                "meta": dict(meta) if isinstance(meta, dict) else {},
                "strings": [],
            }
            for string_match in strings:
                if not hasattr(string_match, "identifier") or not hasattr(string_match, "instances"):
                    continue
                instances = getattr(string_match, "instances", [])
                if not isinstance(instances, (list, tuple)):
                    continue
                string_info = {"identifier": string_match.identifier, "instances": []}
                for instance in instances:
                    if not hasattr(instance, "offset") or not hasattr(instance, "matched_data"):
                        continue
                    matched_data_raw = instance.matched_data
                    if isinstance(matched_data_raw, (bytes, bytearray)):
                        matched_data = matched_data_raw.decode("utf-8", errors="ignore")
                        default_length = len(matched_data_raw)
                    else:
                        matched_data = str(matched_data_raw)
                        default_length = len(matched_data)
                    length = getattr(instance, "length", default_length)
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
            for extension in _coerce_extensions(yara_extensions):
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
