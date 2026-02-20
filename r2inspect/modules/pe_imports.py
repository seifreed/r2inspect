#!/usr/bin/env python3
"""PE import/imphash helpers."""

import hashlib
from typing import Any

from ..utils.command_helpers import cmdj as cmdj_helper


def fetch_imports(adapter: Any) -> list[dict[str, Any]]:
    if adapter is not None and hasattr(adapter, "get_imports"):
        imports = adapter.get_imports()
    else:
        imports = cmdj_helper(adapter, None, "iij", [])
    return imports if imports else []


def group_imports_by_library(
    imports: list[dict[str, Any]],
) -> dict[str, list[str | bytes]]:
    imports_by_lib: dict[str, list[str | bytes]] = {}

    for imp in imports:
        if not isinstance(imp, dict) or "name" not in imp:
            continue

        libname = imp.get("libname", "unknown")
        if not libname or libname.strip() == "":
            libname = "unknown"

        funcname = imp.get("name", "")
        if not funcname or funcname.strip() == "":
            continue

        imports_by_lib.setdefault(libname, []).append(funcname)

    return imports_by_lib


def normalize_library_name(lib_name: str | bytes, extensions: list[str]) -> str:
    if isinstance(lib_name, bytes):
        lib_name = lib_name.decode(errors="ignore")

    lib_name = lib_name.lower()

    parts = lib_name.rsplit(".", 1)
    if len(parts) > 1 and parts[1] in extensions:
        lib_name = parts[0]

    return lib_name


def compute_imphash(import_strings: list[str]) -> str:
    if not import_strings:
        return ""

    imphash_string = ",".join(import_strings)
    return hashlib.md5(imphash_string.encode("utf-8"), usedforsecurity=False).hexdigest()


def calculate_imphash(adapter: Any, logger: Any) -> str:
    try:
        logger.debug("Calculating imphash using pefile-compatible algorithm...")

        imports = fetch_imports(adapter)
        if not imports:
            logger.debug("No imports found for imphash calculation")
            return ""

        imports_by_lib = group_imports_by_library(imports)
        extensions = ["ocx", "sys", "dll"]

        impstrs: list[str] = []
        for libname, functions in imports_by_lib.items():
            normalized_lib = normalize_library_name(libname, extensions)

            for funcname in functions:
                if not funcname:  # pragma: no cover
                    continue  # pragma: no cover

                if isinstance(funcname, bytes):
                    funcname = funcname.decode(errors="ignore")

                impstr = f"{normalized_lib}.{funcname.lower()}"
                impstrs.append(impstr)

        if not impstrs:
            logger.debug("No valid import strings found for imphash")
            return ""

        imphash = compute_imphash(impstrs)
        logger.debug(f"Imphash calculated: {imphash} (from {len(impstrs)} imports)")
        return imphash

    except Exception as exc:
        logger.error(f"Error calculating imphash: {exc}")
        return ""
