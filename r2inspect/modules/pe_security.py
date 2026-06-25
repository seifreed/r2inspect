#!/usr/bin/env python3
"""PE security feature helpers."""

from __future__ import annotations

from typing import Any

from ..abstractions.coercion_support import coerce_int, coerce_int_or_none
from ..domain.formats.pe_info import find_pe_data_directory
from ..infrastructure.r2_helpers import get_pe_headers


def _parse_dll_characteristics(value: Any) -> int | None:
    return coerce_int_or_none(value)


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
            security_info = _get_pe_security_text(adapter)
            _apply_security_flags_from_text(features, security_info)

        _apply_authenticode_feature(features, adapter)

    except Exception as exc:
        logger.error("Error checking security features: %s", exc)

    return features


def _apply_security_flags_from_header(
    features: dict[str, bool], pe_header: dict[str, Any] | None, logger: Any
) -> None:
    if not pe_header:
        return
    opt_header = pe_header.get("optional_header", {})
    if not isinstance(opt_header, dict):
        return
    dll_characteristics = _parse_dll_characteristics(opt_header.get("DllCharacteristics", 0))
    if dll_characteristics is None:
        return

    features["aslr"] = bool(dll_characteristics & 0x0040)
    features["dep"] = bool(dll_characteristics & 0x0100)
    features["seh"] = not bool(dll_characteristics & 0x0400)
    features["guard_cf"] = bool(dll_characteristics & 0x4000)

    logger.debug("DllCharacteristics: 0x%04x", dll_characteristics)
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


def _get_pe_security_text(adapter: Any) -> str:
    getter = getattr(adapter, "get_pe_security_text", None)
    if callable(getter):
        result = getter()
        return result if isinstance(result, str) else str(result)
    from ..infrastructure.command_helpers import cmd as cmd_helper

    return str(cmd_helper(adapter, None, "iHH"))


def _apply_authenticode_feature(features: dict[str, bool], adapter: Any) -> None:
    # The certificate table lives in the SECURITY data directory, which radare2
    # exposes only inside the ``ihj`` field list (``iDj`` returns {}). The old
    # code read ``pe_header["data_directories"]["security"]``, a key the header
    # parser never builds, so this was False for every signed PE.
    security_dir = find_pe_data_directory(adapter.cmdj("ihj"), "SECURITY")
    if security_dir and coerce_int(security_dir.get("size", 0)) > 0:
        features["authenticode"] = True
