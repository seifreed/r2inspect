#!/usr/bin/env python3
"""Helper functions for anti-analysis detection."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def collect_artifact_strings(
    strings_result: list[dict[str, Any]] | None, artifacts: list[str]
) -> list[dict[str, Any]]:
    if not strings_result:
        return []
    matches: list[dict[str, Any]] = []
    for string_info in strings_result:
        string_val = string_info.get("string", "")
        for artifact in artifacts:
            if artifact.lower() in string_val.lower():
                matches.append(
                    {
                        "artifact": artifact,
                        "string": string_val,
                        "address": hex(string_info.get("vaddr", 0)),
                    }
                )
    return matches


def add_simple_evidence(
    result: dict[str, Any],
    checks: str,
    evidence_type: str,
    detail_prefix: str,
    field: str,
    limit: int,
) -> None:
    if not checks or not checks.strip():
        return
    result["detected"] = True
    items = checks.strip().split("\n")[:limit]
    detail = (
        f"{detail_prefix} at {len(checks.strip().splitlines())} locations"
        if field == "addresses"
        else detail_prefix
    )
    result["evidence"].append({"type": evidence_type, "detail": detail, field: items})


def count_opcode_occurrences(search_fn: Callable[[str], str], pattern: str) -> int:
    output = search_fn(pattern)
    if not output or not output.strip():
        return 0
    return len(output.strip().split("\n"))


def detect_obfuscation(search_fn: Callable[[str], str]) -> list[dict[str, Any]]:
    techniques: list[dict[str, Any]] = []
    jmp_count = count_opcode_occurrences(search_fn, "jmp")
    call_count = count_opcode_occurrences(search_fn, "call")
    if jmp_count > 100 or call_count > 200:
        techniques.append(
            {
                "technique": "Code Obfuscation",
                "description": f"High number of jumps ({jmp_count}) and calls ({call_count})",
                "severity": "Medium",
            }
        )
    return techniques


def detect_self_modifying(cmd_fn: Callable[[str], str]) -> list[dict[str, Any]]:
    modify_patterns = cmd_fn("/c mov.*cs:|/c mov.*ds:")
    if modify_patterns and modify_patterns.strip():
        return [
            {
                "technique": "Self-Modifying Code",
                "description": "Code segment modifications detected",
                "severity": "High",
            }
        ]
    return []


def detect_api_hashing(cmd_fn: Callable[[str], str]) -> list[dict[str, Any]]:
    hash_patterns = cmd_fn("iz~hash|iz~crc32|iz~fnv")
    if hash_patterns and hash_patterns.strip():
        return [
            {
                "technique": "API Hashing",
                "description": "Hash-based API resolution detected",
                "severity": "Medium",
            }
        ]
    return []


def detect_injection_apis(
    imports: list[dict[str, Any]] | None, injection_apis: set[str]
) -> list[dict[str, Any]]:
    injection_found = 0
    for imp in imports or []:
        if imp.get("name") in injection_apis:
            injection_found += 1
    if injection_found >= 2:
        return [
            {
                "technique": "DLL Injection",
                "description": f"Process injection APIs detected ({injection_found})",
                "severity": "High",
            }
        ]
    return []


def match_suspicious_api(
    imp: dict[str, Any], suspicious_api_categories: dict[str, list[str]]
) -> dict[str, Any] | None:
    imp_name = imp.get("name", "")
    for category, apis in suspicious_api_categories.items():
        for api in apis:
            if api in imp_name:
                return {
                    "api": imp_name,
                    "category": category,
                    "address": hex(imp.get("plt", 0)),
                }
    return None


def detect_environment_checks(
    cmd_fn: Callable[[str], str], env_commands: list[tuple[str, str, str]]
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for command, check_type, description in env_commands:
        output = cmd_fn(command)
        if output and output.strip():
            checks.append({"type": check_type, "description": description})
    return checks
