#!/usr/bin/env python3
"""Helper functions for anti-analysis detection."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..abstractions.coercion_support import coerce_int


def _to_int(value: Any) -> int:
    return coerce_int(value)


def _string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def collect_artifact_strings(
    strings_result: list[dict[str, Any]] | None, artifacts: list[str]
) -> list[dict[str, Any]]:
    import re

    if not strings_result:
        return []
    matches: list[dict[str, Any]] = []
    # Pre-compile word-boundary patterns to avoid substring false positives
    # e.g., "virus" should not match "antivirus", "sample" should not match "Example"
    patterns = {
        artifact: re.compile(r"\b" + re.escape(artifact) + r"\b", re.IGNORECASE)
        for artifact in artifacts
    }
    for string_info in strings_result:
        if not isinstance(string_info, dict):
            continue
        string_val = _string_value(string_info.get("string"))
        if not string_val:
            continue
        for artifact, pattern in patterns.items():
            if pattern.search(string_val):
                matches.append(
                    {
                        "artifact": artifact,
                        "string": string_val,
                        "address": hex(_to_int(string_info.get("vaddr", 0))),
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
    if not isinstance(checks, str) or not checks.strip():
        return
    evidence = result.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
        result["evidence"] = evidence
    result["detected"] = True
    items = checks.strip().split("\n")[:limit]
    detail = (
        f"{detail_prefix} at {len(checks.strip().splitlines())} locations"
        if field == "addresses"
        else detail_prefix
    )
    evidence.append({"type": evidence_type, "detail": detail, field: items})


def count_opcode_occurrences(search_fn: Callable[[str], str], pattern: str) -> int:
    output = search_fn(pattern)
    if not isinstance(output, str) or not output.strip():
        return 0
    return len(output.strip().split("\n"))


def detect_obfuscation(
    search_fn: Callable[[str], str],
    code_size_bytes: int = 0,
) -> list[dict[str, Any]]:
    techniques: list[dict[str, Any]] = []
    jmp_count = count_opcode_occurrences(search_fn, "jmp")
    call_count = count_opcode_occurrences(search_fn, "call")

    # Normalize thresholds by code size to avoid false positives on large binaries.
    # Use density: >1 jmp per 100 bytes or >2 calls per 100 bytes is suspicious.
    if code_size_bytes > 0:
        jmp_density = (jmp_count / code_size_bytes) * 100
        call_density = (call_count / code_size_bytes) * 100
        is_obfuscated = jmp_density > 1.0 or call_density > 2.0
    else:
        # Fallback to absolute thresholds when code size is unknown.
        # These match the original pre-refactor sensitivity (>100 jmps or
        # >200 calls); commit 8f3da63 silently raised them to 500/1000,
        # which regressed obfuscation detection for unsized code.
        is_obfuscated = jmp_count > 100 or call_count > 200

    if is_obfuscated:
        techniques.append(
            {
                "technique": "Code Obfuscation",
                "description": f"High density of jumps ({jmp_count}) and calls ({call_count})",
                "severity": "Medium",
            }
        )
    return techniques


def detect_self_modifying(cmd_fn: Callable[[str], str]) -> list[dict[str, Any]]:
    modify_patterns = cmd_fn("/c mov.*cs:|/c mov.*ds:")
    if isinstance(modify_patterns, str) and modify_patterns.strip():
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
    if isinstance(hash_patterns, str) and hash_patterns.strip():
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
    if isinstance(imports, list):
        import_source = imports
    else:
        try:
            import_source = list(imports or [])
        except TypeError:
            import_source = []
    for imp in import_source:
        if not isinstance(imp, dict):
            continue
        if _string_value(imp.get("name")) in injection_apis:
            injection_found += 1
    # Two or more injection-related APIs together are the established
    # detection threshold. Commit 8f3da63 silently raised this to 3 under a
    # "refactor" label, regressing detection of classic 2-call injection
    # (e.g. WriteProcessMemory + CreateRemoteThread).
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
    if not isinstance(imp, dict):
        return None
    imp_name = _string_value(imp.get("name"))
    for category, apis in suspicious_api_categories.items():
        for api in apis:
            if api in imp_name:
                return {
                    "api": imp_name,
                    "category": category,
                    "address": hex(_to_int(imp.get("plt", 0))),
                }
    return None


def detect_environment_checks(
    cmd_fn: Callable[[str], str], env_commands: list[tuple[str, str, str]]
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for command, check_type, description in env_commands:
        output = cmd_fn(command)
        if isinstance(output, str) and output.strip():
            checks.append({"type": check_type, "description": description})
    return checks
