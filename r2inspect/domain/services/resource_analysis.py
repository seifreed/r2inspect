"""Pure domain services for PE resource analysis."""

from __future__ import annotations

from typing import Any


def _resource_name(resource: dict[str, Any]) -> str:
    value = resource.get("name")
    if isinstance(value, str) and value:
        return value
    type_name = resource.get("type_name")
    if isinstance(type_name, str) and type_name:
        return type_name
    return "UNKNOWN"


def _resource_type_name(resource: dict[str, Any]) -> str:
    value = resource.get("type_name")
    if isinstance(value, str) and value:
        return value
    return "UNKNOWN"


def _coerce_int(value: Any) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_float(value: Any) -> float | None:
    try:
        if isinstance(value, str):
            return float(value)
        if isinstance(value, (int, float)):
            return float(value)
    except (TypeError, ValueError):
        return None
    return None


def _resource_size(resource: dict[str, Any]) -> int:
    return _coerce_int(resource.get("size", 0))


def _resource_offset(resource: dict[str, Any]) -> int:
    return _coerce_int(resource.get("offset", 0))


def summarize_resource_types(resources: list[Any]) -> tuple[list[dict[str, Any]], int]:
    """Build type counts and total size summary for resources."""
    type_counts: dict[str, int] = {}
    type_sizes: dict[str, int] = {}

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        type_name = _resource_type_name(resource)
        type_counts[type_name] = type_counts.get(type_name, 0) + 1
        type_sizes[type_name] = type_sizes.get(type_name, 0) + _resource_size(resource)

    summary = [
        {
            "type": type_name,
            "count": count,
            "total_size": type_sizes.get(type_name, 0),
        }
        for type_name, count in type_counts.items()
    ]
    return summary, sum(type_sizes.values())


def build_icon_entries(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract icon metadata and mark obviously suspicious icons."""
    icons: list[dict[str, Any]] = []

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if resource.get("type_name") not in ["RT_ICON", "RT_GROUP_ICON"]:
            continue

        icon_info: dict[str, Any] = {
            "type": _resource_type_name(resource),
            "size": _resource_size(resource),
            "offset": _resource_offset(resource),
            "entropy": _resource_entropy(resource),
        }
        if icon_info["entropy"] > 7.5:
            icon_info["suspicious"] = "High entropy (possibly encrypted)"
        icons.append(icon_info)

    return icons


def _decode_printable(raw: bytes, encoding: str) -> str | None:
    """Decode bytes with the given encoding, returning text only when printable."""
    text = raw.decode(encoding, errors="ignore")
    if text and any(char.isprintable() for char in text):
        return text
    return None


def _looks_like_utf16(raw: bytes) -> bool:
    """Heuristic for UTF-16LE text: enough interleaved NUL bytes."""
    return len(raw) >= 4 and raw.count(0) >= max(2, len(raw) // 8)


def decode_resource_text(raw: bytes) -> str | None:
    """Decode resource bytes as UTF-16LE, UTF-8, or ASCII when printable."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        return None

    encodings = ["utf-16le", "utf-8", "ascii"] if _looks_like_utf16(raw) else ["utf-8", "ascii"]
    for encoding in encodings:
        text = _decode_printable(raw, encoding)
        if text is not None:
            return text
    return None


def build_manifest_info(manifest_data: str, size: int) -> dict[str, Any]:
    """Summarize manifest content into stable flags."""
    manifest_text = manifest_data if isinstance(manifest_data, str) else str(manifest_data or "")
    return {
        "content": manifest_text[:2048],
        "size": size,
        "requires_admin": "requireAdministrator" in manifest_text,
        "requires_elevation": "highestAvailable" in manifest_text,
        "dpi_aware": "dpiAware" in manifest_text,
    }


def _positive_entropy(resource: dict[str, Any]) -> float | None:
    """Return a resource's entropy when it is a positive number, else None."""
    value = _coerce_float(resource.get("entropy", 0))
    return value if value is not None and value > 0 else None


def _resource_entropy(resource: dict[str, Any]) -> float:
    value = _coerce_float(resource.get("entropy", 0.0))
    return value if value is not None else 0.0


def _size_statistics(sizes: list[int]) -> dict[str, Any]:
    """Aggregate size statistics, collapsing to zeros for an empty inventory."""
    if not sizes:
        return {"total_size": 0, "average_size": 0, "max_size": 0, "min_size": 0}
    return {
        "total_size": sum(sizes),
        "average_size": sum(sizes) // len(sizes),
        "max_size": max(sizes),
        "min_size": min(sizes),
    }


def _entropy_statistics(entropies: list[float]) -> dict[str, Any]:
    """Aggregate entropy statistics, collapsing to zeros when none are present."""
    if not entropies:
        return {"average_entropy": 0, "max_entropy": 0}
    return {
        "average_entropy": sum(entropies) / len(entropies),
        "max_entropy": max(entropies),
    }


def build_resource_statistics(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate statistics for a resource inventory."""
    if not resources:
        return {}

    valid_resources = [resource for resource in resources if isinstance(resource, dict)]
    sizes = [size for resource in valid_resources if (size := _resource_size(resource)) > 0]
    entropies = [
        entropy
        for resource in valid_resources
        if (entropy := _positive_entropy(resource)) is not None
    ]

    stats: dict[str, Any] = {"total_resources": len(valid_resources)}
    stats.update(_size_statistics(sizes))
    stats.update(_entropy_statistics(entropies))
    stats["unique_types"] = len({_resource_type_name(resource) for resource in valid_resources})
    return stats


def check_resource_entropy(resource: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag high-entropy non-icon resources."""
    entropy = _resource_entropy(resource)
    if entropy <= 7.5:
        return []
    type_name = _resource_type_name(resource)
    if type_name in ["RT_ICON", "RT_BITMAP"]:
        return []
    return [
        {
            "resource": _resource_name(resource),
            "reason": "High entropy (possibly encrypted/packed)",
            "entropy": entropy,
            "size": _resource_size(resource),
        }
    ]


def check_resource_size(resource: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag unusually large resources."""
    size = _resource_size(resource)
    if size <= 1024 * 1024:
        return []
    return [
        {
            "resource": _resource_name(resource),
            "reason": "Unusually large resource",
            "size": size,
        }
    ]


def check_resource_rcdata(resource: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag large RCDATA blobs that may carry embedded content."""
    type_name = _resource_type_name(resource)
    size = _resource_size(resource)
    if type_name != "RT_RCDATA" or size <= 10240:
        return []
    return [
        {
            "resource": _resource_name(resource),
            "reason": "Large RCDATA resource (may contain embedded data)",
            "size": size,
            "entropy": resource.get("entropy", 0),
        }
    ]


def is_embedded_pe_header(header_data: list[int] | None) -> bool:
    """Check whether the provided bytes start with an MZ header."""
    return bool(
        header_data and len(header_data) >= 2 and header_data[0] == 0x4D and header_data[1] == 0x5A
    )


def check_resource_embedded_pe(
    resource: dict[str, Any], header_data: list[int] | None
) -> list[dict[str, Any]]:
    """Flag resources that appear to contain an embedded PE file."""
    type_name = _resource_type_name(resource)
    size = _resource_size(resource)
    offset = _resource_offset(resource)
    if type_name not in ["RT_RCDATA", "UNKNOWN"]:
        return []
    if size <= 1024 or offset <= 0:
        return []
    if not is_embedded_pe_header(header_data):
        return []
    return [
        {
            "resource": _resource_name(resource),
            "reason": "Possible embedded PE file",
            "size": size,
        }
    ]


def build_suspicious_resources(
    resources: list[dict[str, Any]],
    header_reader: Any,
) -> list[dict[str, Any]]:
    """Collect suspicious resource indicators, deferring header reads via callback."""
    suspicious: list[dict[str, Any]] = []

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        suspicious.extend(check_resource_entropy(resource))
        suspicious.extend(check_resource_size(resource))
        suspicious.extend(check_resource_rcdata(resource))

        header_data = None
        type_name = _resource_type_name(resource)
        if (
            type_name in ["RT_RCDATA", "UNKNOWN"]
            and _resource_size(resource) > 1024
            and _resource_offset(resource) > 0
        ):
            header_data = header_reader(resource)
        suspicious.extend(check_resource_embedded_pe(resource, header_data))

    return suspicious
