#!/usr/bin/env python3
"""String classification helpers."""

from __future__ import annotations

import re

API_PATTERNS = [
    "CreateFile",
    "WriteFile",
    "ReadFile",
    "RegOpenKey",
    "GetProcAddress",
    "LoadLibrary",
    "VirtualAlloc",
    "CreateThread",
    "CreateProcess",
]

REGISTRY_ROOT_PATTERN = re.compile(
    r"^(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC|SOFTWARE|SYSTEM)\\",
    re.IGNORECASE,
)


def is_api_string(value: str) -> bool:
    return any(pattern.lower() in value.lower() for pattern in API_PATTERNS)


def is_path_string(value: str) -> bool:
    return ("\\" in value or "/" in value) and (len(value) > 3) and not value.startswith("http")


def is_url_string(value: str) -> bool:
    return value.startswith(("http://", "https://", "ftp://"))


def is_registry_string(value: str) -> bool:
    return REGISTRY_ROOT_PATTERN.match(value) is not None


def classify_string_type(value: str) -> str | None:
    if re.match(r"https?://", value, re.IGNORECASE):
        return "url"
    if re.match(r"[a-z]:\\", value, re.IGNORECASE) or value.startswith("/"):
        return "path"
    if is_registry_string(value):
        return "registry"
    if re.match(r"^[A-Z][\\w]*[A-Z]", value) or is_api_string(value):
        return "api"
    if any(word in value.lower() for word in ["error", "failed", "exception", "invalid"]):
        return "error"
    return None
