"""DEPRECATED: Import from r2inspect.domain.formats.macho instead."""

from ..domain.formats.macho import (
    SDK_VERSION_MAP,
    estimate_from_sdk_version,
    platform_from_version_min,
    dylib_timestamp_to_string,
    build_load_commands,
    build_sections,
)

__all__ = [
    "SDK_VERSION_MAP",
    "estimate_from_sdk_version",
    "platform_from_version_min",
    "dylib_timestamp_to_string",
    "build_load_commands",
    "build_sections",
]
