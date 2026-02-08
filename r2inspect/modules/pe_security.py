#!/usr/bin/env python3
"""PE security feature helpers."""

from __future__ import annotations

from typing import Any

from ..utils.command_helpers import cmd as cmd_helper
from ..utils.r2_helpers import get_pe_headers


def get_security_features(adapter: Any, logger: Any) -> dict[str, bool]:
    features = {
        "aslr": False,
        "dep": False,
        "seh": False,
        "guard_cf": False,
        "authenticode": False,
    }

    try:
        pe_header = get_pe_headers(adapter)
        _apply_security_flags_from_header(features, pe_header, logger)

        if not any(features.values()):
            security_info = cmd_helper(adapter, None, "iHH")
            _apply_security_flags_from_text(features, security_info)

        _apply_authenticode_feature(features, pe_header)

    except Exception as exc:
        logger.error(f"Error checking security features: {exc}")

    return features


def _apply_security_flags_from_header(
    features: dict[str, bool], pe_header: dict[str, Any] | None, logger: Any
) -> None:
    if not pe_header:
        return
    opt_header = pe_header.get("optional_header", {})
    dll_characteristics = opt_header.get("DllCharacteristics", 0)
    if not isinstance(dll_characteristics, int):
        return

    features["aslr"] = bool(dll_characteristics & 0x0040)
    features["dep"] = bool(dll_characteristics & 0x0100)
    features["seh"] = not bool(dll_characteristics & 0x0400)
    features["guard_cf"] = bool(dll_characteristics & 0x4000)

    logger.debug(f"DllCharacteristics: 0x{dll_characteristics:04x}")
    logger.debug(
        "Security features: ASLR=%s, DEP=%s, SEH=%s, CFG=%s",
        features["aslr"],
        features["dep"],
        features["seh"],
        features["guard_cf"],
    )


def _apply_security_flags_from_text(features: dict[str, bool], security_info: str | None) -> None:
    if not security_info:
        return
    if "DLL can move" in security_info or "DYNAMIC_BASE" in security_info:
        features["aslr"] = True
    if "NX_COMPAT" in security_info:
        features["dep"] = True
    if "NO_SEH" not in security_info:
        features["seh"] = True
    if "GUARD_CF" in security_info:
        features["guard_cf"] = True


def _apply_authenticode_feature(
    features: dict[str, bool], pe_header: dict[str, Any] | None
) -> None:
    if not pe_header:
        return
    data_dir = pe_header.get("data_directories", {})
    security_dir = data_dir.get("security", {})
    if isinstance(security_dir, dict) and security_dir.get("size", 0) > 0:
        features["authenticode"] = True
