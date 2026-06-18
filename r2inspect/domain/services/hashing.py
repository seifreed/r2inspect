"""Pure hashing services."""

from __future__ import annotations

import hashlib
from typing import Any


def calculate_hashes_for_bytes(data: bytes, *, include_sha512: bool = False) -> dict[str, str]:
    """Calculate hashes for an in-memory bytes buffer."""
    hashes = {"md5": "", "sha1": "", "sha256": ""}
    if include_sha512:
        hashes["sha512"] = ""

    hashes["md5"] = hashlib.md5(data, usedforsecurity=False).hexdigest()
    hashes["sha1"] = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    hashes["sha256"] = hashlib.sha256(data).hexdigest()
    if include_sha512:
        hashes["sha512"] = hashlib.sha512(data).hexdigest()

    return hashes


def calculate_imphash(imports: list[Any]) -> str | None:
    """Calculate import hash (imphash) from import entries."""
    try:
        if not imports:
            return None

        import_string = ""
        for imp in imports:
            lib = imp.get("library", imp.get("dll", imp.get("libname", ""))).lower()
            # The imphash spec (Mandiant/pefile) strips the module extension so
            # the token is "kernel32.createfile", not "kernel32.dll.createfile";
            # otherwise the hash matches no public imphash IOC.
            parts = lib.rsplit(".", 1)
            if len(parts) > 1 and parts[1] in ("ocx", "sys", "dll"):
                lib = parts[0]
            func = imp.get("name", "").lower()
            if lib and func:
                import_string += f"{lib}.{func},"

        if not import_string:
            return None

        import_string = import_string.rstrip(",")
        return hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()

    except Exception:
        return None
