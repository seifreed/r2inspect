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


def _decode_import_field(value: Any) -> str | None:
    """Coerce a raw import field to a lowercase string, or ``None`` if it is not text."""
    if isinstance(value, bytes):
        value = value.decode(errors="ignore")
    if not isinstance(value, str):
        return None
    return value.lower()


def _strip_module_extension(lib: str) -> str:
    """Strip the module extension from a library name.

    The imphash spec (Mandiant/pefile) strips the extension so the token is
    "kernel32.createfile", not "kernel32.dll.createfile"; otherwise the hash
    matches no public imphash IOC.
    """
    head, _, ext = lib.rpartition(".")
    if head and ext in ("ocx", "sys", "dll"):
        return head
    return lib


def _imphash_token(imp: Any) -> str | None:
    """Build the ``library.function`` imphash token for one import entry."""
    if not isinstance(imp, dict):
        return None
    lib = _decode_import_field(imp.get("library") or imp.get("dll") or imp.get("libname") or "")
    func = _decode_import_field(imp.get("name") or "")
    if lib is None or func is None:
        return None
    lib = _strip_module_extension(lib)
    if lib and func:
        return f"{lib}.{func}"
    return None


def calculate_imphash(imports: list[Any]) -> str | None:
    """Calculate import hash (imphash) from import entries."""
    tokens = [token for imp in imports or [] if (token := _imphash_token(imp))]
    if not tokens:
        return None
    import_string = ",".join(tokens)
    return hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()
