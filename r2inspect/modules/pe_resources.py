#!/usr/bin/env python3
"""PE resource helpers."""

from typing import Any

from ..utils.command_helpers import cmd as cmd_helper
from ..utils.command_helpers import cmdj as cmdj_helper
from .pe_info_domain import normalize_resource_entries, parse_version_info_text


def get_resource_info(adapter: Any, logger: Any) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []

    try:
        res_info = cmdj_helper(adapter, None, "iRj", [])
        if res_info:
            resources.extend(normalize_resource_entries(res_info))
    except Exception as exc:
        logger.error(f"Error getting resource info: {exc}")

    return resources


def get_version_info(adapter: Any, logger: Any) -> dict[str, str]:
    version_info: dict[str, str] = {}

    try:
        version_result = cmd_helper(adapter, None, "iR~version")
        if version_result:
            version_info = parse_version_info_text(version_result)
    except Exception as exc:
        logger.error(f"Error getting version info: {exc}")

    return version_info
