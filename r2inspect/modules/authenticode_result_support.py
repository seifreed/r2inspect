"""Result helpers for Authenticode analysis."""

from __future__ import annotations

from typing import Any

from ..abstractions.coercion_support import coerce_int


def init_authenticode_result(init_result_structure: Any) -> dict[str, Any]:
    result: dict[str, Any] = init_result_structure(
        {
            "has_signature": False,
            "signature_valid": False,
            "certificates": [],
            "timestamp": None,
            "signature_offset": None,
            "signature_size": None,
            "security_directory": None,
            "errors": [],
        }
    )
    result["available"] = True
    return result


def apply_security_directory(result: dict[str, Any], security_dir: dict[str, Any]) -> None:
    result["has_signature"] = True
    result["security_directory"] = {
        "offset": coerce_int(security_dir.get("paddr", 0)),
        "size": coerce_int(security_dir.get("size", 0)),
        "virtual_address": coerce_int(security_dir.get("vaddr", 0)),
    }
