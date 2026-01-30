#!/usr/bin/env python3
"""
Hashing utilities for r2inspect
"""

import hashlib
import os
from typing import cast


def calculate_hashes(file_path: str) -> dict[str, str]:
    """Calculate various hashes for a file"""
    hashes = {"md5": "", "sha1": "", "sha256": "", "sha512": ""}

    try:
        if not os.path.exists(file_path):
            return hashes

        # Create hash objects
        md5_hash = hashlib.md5(usedforsecurity=False)
        sha1_hash = hashlib.sha1(usedforsecurity=False)
        sha256_hash = hashlib.sha256()
        sha512_hash = hashlib.sha512()

        # Read file in chunks to handle large files
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                sha512_hash.update(chunk)

        # Get hex digests
        hashes["md5"] = md5_hash.hexdigest()
        hashes["sha1"] = sha1_hash.hexdigest()
        hashes["sha256"] = sha256_hash.hexdigest()
        hashes["sha512"] = sha512_hash.hexdigest()

    except Exception as e:
        # Return empty hashes on error
        for key in hashes:
            hashes[key] = f"Error: {str(e)}"

    return hashes


def calculate_imphash(imports: list) -> str | None:
    """Calculate import hash (imphash) from imports list"""
    try:
        if not imports:
            return None

        # Create import string
        import_string = ""
        for imp in imports:
            lib = imp.get("library", "").lower()
            func = imp.get("name", "").lower()
            if lib and func:
                import_string += f"{lib}.{func},"

        if not import_string:
            return None

        # Remove trailing comma
        import_string = import_string.rstrip(",")

        # Calculate MD5 of import string
        return hashlib.md5(import_string.encode(), usedforsecurity=False).hexdigest()

    except Exception:
        return None


def calculate_ssdeep(file_path: str) -> str | None:
    """Calculate ssdeep fuzzy hash (requires ssdeep library)"""
    try:
        import ssdeep

        return cast(str | None, ssdeep.hash_from_file(file_path))
    except ImportError:
        return None
    except Exception:
        return None
