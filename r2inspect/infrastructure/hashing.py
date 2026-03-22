#!/usr/bin/env python3
"""Infrastructure hashing helpers that touch filesystem or optional libraries."""

from __future__ import annotations

import hashlib
import os
from typing import cast

from ..domain.services.hashing import calculate_hashes_for_bytes, calculate_imphash
from ..infrastructure.ssdeep_loader import get_ssdeep


def calculate_hashes(file_path: str) -> dict[str, str]:
    """Calculate various hashes for a file."""
    hashes = {"md5": "", "sha1": "", "sha256": "", "sha512": ""}

    try:
        if not os.path.exists(file_path):
            return hashes

        md5_hash = hashlib.md5(usedforsecurity=False)
        sha1_hash = hashlib.sha1(usedforsecurity=False)
        sha256_hash = hashlib.sha256()
        sha512_hash = hashlib.sha512()

        with open(file_path, "rb") as file_handle:
            while chunk := file_handle.read(8192):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                sha512_hash.update(chunk)

        hashes["md5"] = md5_hash.hexdigest()
        hashes["sha1"] = sha1_hash.hexdigest()
        hashes["sha256"] = sha256_hash.hexdigest()
        hashes["sha512"] = sha512_hash.hexdigest()

    except Exception:
        pass  # Return pre-initialized empty strings on failure

    return hashes


def calculate_ssdeep(file_path: str) -> str | None:
    """Calculate ssdeep fuzzy hash (requires optional ssdeep library)."""
    try:
        ssdeep_module = get_ssdeep()
        if ssdeep_module is None:
            return None
        return cast(str | None, ssdeep_module.hash_from_file(file_path))
    except Exception:
        return None


__all__ = [
    "calculate_hashes",
    "calculate_hashes_for_bytes",
    "calculate_imphash",
    "calculate_ssdeep",
]
