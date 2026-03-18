"""Helper operations for resource analyzer."""

from __future__ import annotations

from typing import Any

from ..domain.services.resource_analysis import (
    build_icon_entries,
    build_manifest_info,
    build_resource_statistics,
    build_suspicious_resources,
    decode_resource_text,
)


def _coerce_resource_int(resource: dict[str, Any], field: str) -> int | None:
    value = resource.get(field, 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return None


def _resource_debug_name(resource: dict[str, Any]) -> str:
    return str(resource.get("name") or resource.get("type_name", "UNKNOWN"))


def analyze_resource_data(
    analyzer: Any,
    resource: dict[str, Any],
    *,
    logger: Any,
    calculate_hashes_for_bytes: Any,
) -> None:
    try:
        resource.setdefault("entropy", 0.0)
        resource.setdefault("hashes", {})
        offset = _coerce_resource_int(resource, "offset")
        size = _coerce_resource_int(resource, "size")
        if offset is None or size is None:
            logger.debug(
                "Skipping resource with invalid offset/size: %s", _resource_debug_name(resource)
            )
            return
        size = min(size, 65536)
        if offset == 0 or size == 0:
            return
        data = analyzer._cmdj(f"pxj {size} @ {offset}", [])
        if not data:
            return
        resource["entropy"] = analyzer._calculate_entropy(data)
        try:
            resource["hashes"] = calculate_hashes_for_bytes(bytes(data))
        except Exception as exc:
            logger.debug("Error calculating resource hashes: %s", exc)
            resource["hashes"] = {}
    except Exception as exc:
        logger.error(
            "Error analyzing resource data for %s: %s", _resource_debug_name(resource), exc
        )


def read_resource_as_string(analyzer: Any, offset: int, size: int, *, logger: Any) -> str | None:
    try:
        if offset <= 0 or size <= 0:
            return None
        read_size = min(size, 8192)
        data = analyzer._cmdj(f"pxj {read_size} @ {offset}", [])
        if not data:
            return None
        return decode_resource_text(bytes(data))
    except Exception as exc:
        logger.error("Error reading resource as string at %s (%s bytes): %s", offset, size, exc)
        return None


def extract_version_info(
    analyzer: Any, result: dict[str, Any], resources: list[dict[str, Any]], *, logger: Any
) -> None:
    for res in resources:
        if res.get("type_name") == "RT_VERSION":
            try:
                offset = _coerce_resource_int(res, "offset")
                size = _coerce_resource_int(res, "size")
                if offset is None or size is None:
                    logger.debug(
                        "Skipping version resource with invalid offset/size: %s",
                        _resource_debug_name(res),
                    )
                    continue
                version_data = analyzer._parse_version_info(offset, size)
                if version_data:
                    result["version_info"] = version_data
                    break
            except Exception as exc:
                logger.debug(
                    "Error extracting version info from resource %s: %s",
                    _resource_debug_name(res),
                    exc,
                )


def parse_version_info(
    analyzer: Any, offset: int, size: int, *, logger: Any
) -> dict[str, Any] | None:
    try:
        if offset == 0 or size < 64:
            return None
        data = analyzer._read_version_info_data(offset, size)
        if not data:
            return None
        version_info = {
            "signature": "",
            "file_version": "",
            "product_version": "",
            "file_flags": [],
            "file_os": "",
            "file_type": "",
            "strings": {},
        }
        sig_pos = analyzer._find_vs_signature(data)
        if sig_pos >= 0:
            file_version = analyzer._parse_fixed_file_info(data, sig_pos)
            if file_version:
                version_info["file_version"] = file_version
        version_info["strings"] = analyzer._extract_version_strings(data)
        return version_info if version_info["strings"] else None
    except Exception as exc:
        logger.error("Error parsing version info: %s", exc)
        return None


def extract_manifest(
    analyzer: Any, result: dict[str, Any], resources: list[dict[str, Any]], *, logger: Any
) -> None:
    for res in resources:
        if res.get("type_name") == "RT_MANIFEST":
            try:
                offset = _coerce_resource_int(res, "offset")
                size = _coerce_resource_int(res, "size")
                if offset is None or size is None:
                    logger.debug(
                        "Skipping manifest resource with invalid offset/size: %s",
                        _resource_debug_name(res),
                    )
                    continue
                manifest_data = analyzer._read_resource_as_string(offset, size)
                if manifest_data:
                    result["manifest"] = build_manifest_info(manifest_data, size)
                    break
            except Exception as exc:
                logger.debug(
                    "Error extracting manifest from resource %s: %s", _resource_debug_name(res), exc
                )


def extract_icons(result: dict[str, Any], resources: list[dict[str, Any]]) -> None:
    result["icons"] = build_icon_entries(resources)


def extract_strings(
    analyzer: Any,
    result: dict[str, Any],
    resources: list[dict[str, Any]],
    *,
    logger: Any,
    split_null_terminated: Any,
) -> None:
    strings: list[str] = []
    for res in resources:
        if res.get("type_name") == "RT_STRING":
            try:
                offset = _coerce_resource_int(res, "offset")
                size = _coerce_resource_int(res, "size")
                if offset is None or size is None:
                    logger.debug(
                        "Skipping string resource with invalid offset/size: %s",
                        _resource_debug_name(res),
                    )
                    continue
                string_data = analyzer._read_resource_as_string(offset, size)
                if string_data:
                    strings.extend(split_null_terminated(string_data, min_length=4, limit=20))
            except Exception as exc:
                logger.debug(
                    "Error extracting strings from resource %s: %s", _resource_debug_name(res), exc
                )
    result["strings"] = strings[:50]


def calculate_statistics(result: dict[str, Any], resources: list[dict[str, Any]]) -> None:
    if resources:
        result["statistics"] = build_resource_statistics(resources)


def check_suspicious_resources(
    analyzer: Any, result: dict[str, Any], resources: list[dict[str, Any]]
) -> None:
    result["suspicious_resources"] = build_suspicious_resources(
        resources,
        lambda resource: analyzer._cmdj(
            f"pxj 2 @ {_coerce_resource_int(resource, 'offset') or 0}",
            [],
        ),
    )
