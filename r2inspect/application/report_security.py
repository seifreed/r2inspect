"""Cross-format security normalization for report/v1."""

from __future__ import annotations

from typing import Any

from ..schemas.report_v1 import MitigationV1, SecurityReportV1
from ..schemas.results_models import AnalysisResult


def _feature(details: dict[str, Any], key: str, fallback: Any = None) -> bool | None:
    value = details.get(key, fallback)
    return None if value is None else bool(value)


def _features(result: AnalysisResult, key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    details = result.to_dict().get(key)
    features = details.get("security_features") if isinstance(details, dict) else None
    if isinstance(features, dict):
        return features, {}
    security = result.security.to_dict()
    return security, security


def _elf_values(result: AnalysisResult) -> tuple[dict[str, Any], dict[str, tuple[Any, str]]]:
    features, fallback = _features(result, "elf_info")
    stack = fallback.get("stack_canary") or fallback.get("canary")
    values = {
        "randomization": (
            _feature(features, "pie", fallback.get("pie")),
            "elf.security_features.pie",
        ),
        "no_execution": (_feature(features, "nx", fallback.get("nx")), "elf.security_features.nx"),
        "stack_protection": (
            _feature(features, "stack_canary", stack),
            "elf.security_features.stack_canary",
        ),
        "control_flow_integrity": (None, "elf.security_features"),
        "signature": (None, "elf.provenance"),
        "relocations": (
            _feature(features, "relro", fallback.get("relro")),
            "elf.security_features.relro",
        ),
        "additional_hardening": (
            _feature(features, "fortify", fallback.get("fortify")),
            "elf.security_features.fortify",
        ),
    }
    return features, values


def _macho_values(result: AnalysisResult) -> tuple[dict[str, Any], dict[str, tuple[Any, str]]]:
    features, fallback = _features(result, "macho_info")
    stack = fallback.get("stack_canary") or fallback.get("canary")
    hardening = [features[name] for name in ("arc", "encrypted") if name in features]
    values = {
        "randomization": (
            _feature(features, "pie", fallback.get("pie")),
            "macho.security_features.pie",
        ),
        "no_execution": (
            _feature(features, "nx", fallback.get("nx")),
            "macho.security_features.nx",
        ),
        "stack_protection": (
            _feature(features, "stack_canary", stack),
            "macho.security_features.stack_canary",
        ),
        "control_flow_integrity": (None, "macho.security_features"),
        "signature": (_feature(features, "signed"), "macho.security_features.signed"),
        "relocations": (
            _feature(features, "pie", fallback.get("pie")),
            "macho.security_features.pie",
        ),
        "additional_hardening": (
            any(map(bool, hardening)) if hardening else None,
            "macho.security_features",
        ),
    }
    return features, values


def _pe_values(result: AnalysisResult) -> tuple[dict[str, Any], dict[str, tuple[Any, str]]]:
    features, fallback = _features(result, "pe_info")
    stack = fallback.get("stack_canary") or fallback.get("canary")
    values = {
        "randomization": (
            _feature(features, "aslr", fallback.get("aslr")),
            "pe.security_features.aslr",
        ),
        "no_execution": (
            _feature(features, "dep", fallback.get("dep")),
            "pe.security_features.dep",
        ),
        "stack_protection": (
            _feature(features, "stack_canary", stack),
            "pe.security_features.stack_canary",
        ),
        "control_flow_integrity": (
            _feature(features, "guard_cf", fallback.get("guard_cf")),
            "pe.security_features.guard_cf",
        ),
        "signature": (
            _feature(features, "authenticode", fallback.get("authenticode")),
            "pe.security_features.authenticode",
        ),
        "relocations": (
            _feature(features, "aslr", fallback.get("aslr")),
            "pe.security_features.aslr",
        ),
        "additional_hardening": (
            _feature(features, "seh", fallback.get("seh")),
            "pe.security_features.seh",
        ),
    }
    return features, values


def normalized_security(result: AnalysisResult) -> SecurityReportV1:
    file_type = result.file_info.file_type.upper()
    features, values = (
        _elf_values(result)
        if file_type.startswith("ELF")
        else _macho_values(result) if "MACH" in file_type else _pe_values(result)
    )
    return SecurityReportV1(
        normalized_mitigations={
            name: MitigationV1(enabled=enabled, source=source)
            for name, (enabled, source) in values.items()
        },
        format_specific=features,
    )
