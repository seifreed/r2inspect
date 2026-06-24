"""Helpers for YARA rule IO, compilation and listing."""

from __future__ import annotations

import signal
import threading
import stat as stat_module
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_YARA_RULE_SUFFIXES = {".yar", ".yara", ".rule", ".rules"}
YARA_RULE_PATTERNS = ("*.yar", "*.yara", "*.rule", "*.rules")


def _coerce_extensions(yara_extensions: Any) -> list[str]:
    if isinstance(yara_extensions, list):
        return [ext for ext in yara_extensions if isinstance(ext, str) and ext]
    try:
        return [ext for ext in list(yara_extensions) if isinstance(ext, str) and ext]
    except TypeError:
        return []


def _is_yara_rule_file(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in _YARA_RULE_SUFFIXES


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


def _as_list_or_none(value: Any) -> list[Any] | None:
    """Coerce a YARA collection to a list, or ``None`` when it is not list-like."""
    if isinstance(value, list):
        return value
    if isinstance(value, (dict, str, bytes)) or not isinstance(value, Iterable):
        return None
    return list(value)


def _parse_instance(instance: Any) -> dict[str, Any] | None:
    if not hasattr(instance, "offset") or not hasattr(instance, "matched_data"):
        return None
    matched_data_raw = instance.matched_data
    if isinstance(matched_data_raw, (bytes, bytearray)):
        matched_data = matched_data_raw.decode("utf-8", errors="ignore")
        default_length = len(matched_data_raw)
    else:
        matched_data = str(matched_data_raw)
        default_length = len(matched_data)
    length = getattr(instance, "length", default_length)
    return {"offset": instance.offset, "matched_data": matched_data, "length": length}


def _parse_string_match(string_match: Any) -> dict[str, Any] | None:
    if not hasattr(string_match, "identifier") or not hasattr(string_match, "instances"):
        return None
    instance_source = _as_list_or_none(getattr(string_match, "instances", []))
    if instance_source is None:
        return None
    instances = [
        parsed for instance in instance_source if (parsed := _parse_instance(instance)) is not None
    ]
    return {"identifier": string_match.identifier, "instances": instances}


def _parse_match(match: Any) -> dict[str, Any] | None:
    if not hasattr(match, "rule") or not hasattr(match, "strings"):
        return None
    string_source = _as_list_or_none(getattr(match, "strings", []))
    if string_source is None:
        return None
    tags = _as_list_or_none(getattr(match, "tags", []))
    meta = getattr(match, "meta", {})
    return {
        "rule": str(getattr(match, "rule", "")),
        "namespace": str(getattr(match, "namespace", "")),
        "tags": list(tags) if tags is not None else [],
        "meta": dict(meta) if isinstance(meta, dict) else {},
        "strings": [
            parsed for sm in string_source if (parsed := _parse_string_match(sm)) is not None
        ],
    }


def process_matches(yara_matches: list[Any], logger: Any) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    try:
        if isinstance(yara_matches, list):
            match_source = yara_matches
        elif isinstance(yara_matches, (dict, str, bytes)) or not isinstance(yara_matches, Iterable):
            return matches
        else:
            try:
                match_source = list(yara_matches)
            except TypeError:
                return matches
        for match in match_source:
            match_info = _parse_match(match)
            if match_info is not None:
                matches.append(match_info)
    except Exception as exc:
        logger.error("Error processing YARA matches: %s", exc)
    return matches


def list_available_rules(
    rules_path: str, yara_extensions: list[str], logger: Any
) -> list[dict[str, Any]]:
    available_rules: list[dict[str, Any]] = []
    path = Path(rules_path)
    try:
        path_stat = path.stat()
    except (FileNotFoundError, ValueError):
        logger.warning("YARA rules path not found: %s", rules_path)
        return available_rules
    if stat_module.S_ISREG(path_stat.st_mode):
        if not _is_yara_rule_file(path):
            return available_rules
        available_rules.append(
            {
                "name": path.name,
                "path": rules_path,
                "size": path_stat.st_size,
                "modified": path_stat.st_mtime,
                "type": "single_file",
            }
        )
        return available_rules
    if stat_module.S_ISDIR(path_stat.st_mode):
        for extension in _coerce_extensions(yara_extensions):
            for rule_file in path.rglob(extension):
                try:
                    file_stat = rule_file.stat()
                    relative_path = rule_file.relative_to(path)
                    available_rules.append(
                        {
                            "name": rule_file.name,
                            "path": str(rule_file),
                            "relative_path": str(relative_path),
                            "size": file_stat.st_size,
                            "modified": file_stat.st_mtime,
                            "type": "directory_file",
                        }
                    )
                except Exception as exc:
                    logger.warning("Error reading file info for %s: %s", rule_file, exc)
                    continue
    logger.info("Found %s YARA rule files total", len(available_rules))
    return available_rules
