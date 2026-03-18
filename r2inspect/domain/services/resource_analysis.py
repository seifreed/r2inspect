"""Pure domain services for PE resource analysis."""

from __future__ import annotations

from typing import Any


def _resource_name(resource: dict[str, Any]) -> str:
    return str(resource.get("name") or resource.get("type_name", "UNKNOWN"))


def _resource_type_name(resource: dict[str, Any]) -> str:
    return str(resource.get("type_name", "UNKNOWN"))


def _resource_size(resource: dict[str, Any]) -> int:
    size = resource.get("size", 0)
    return int(size) if isinstance(size, int | float) else 0


def _resource_offset(resource: dict[str, Any]) -> int:
    offset = resource.get("offset", 0)
    return int(offset) if isinstance(offset, int | float) else 0


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
        if resource.get("type_name") not in ["RT_ICON", "RT_GROUP_ICON"]:
            continue

        icon_info: dict[str, Any] = {
            "type": _resource_type_name(resource),
            "size": _resource_size(resource),
            "offset": _resource_offset(resource),
            "entropy": resource.get("entropy", 0.0),
        }
        if icon_info["entropy"] > 7.5:
            icon_info["suspicious"] = "High entropy (possibly encrypted)"
        icons.append(icon_info)

    return icons


def decode_resource_text(raw: bytes) -> str | None:
    """Decode resource bytes as UTF-16LE, UTF-8, or ASCII when printable."""
    if not raw:
        return None

    if len(raw) >= 4 and raw.count(0) >= max(2, len(raw) // 8):
        try:
            text = raw.decode("utf-16le", errors="ignore")
            if text and any(char.isprintable() for char in text):
                return text
        except (UnicodeDecodeError, TypeError):
            pass

    for encoding in ["utf-8", "ascii"]:
        try:
            text = raw.decode(encoding, errors="ignore")
            if text and any(char.isprintable() for char in text):
                return text
        except (UnicodeDecodeError, TypeError):  # pragma: no cover
            pass

    return None


def build_manifest_info(manifest_data: str, size: int) -> dict[str, Any]:
    """Summarize manifest content into stable flags."""
    return {
        "content": manifest_data[:2048],
        "size": size,
        "requires_admin": "requireAdministrator" in manifest_data,
        "requires_elevation": "highestAvailable" in manifest_data,
        "dpi_aware": "dpiAware" in manifest_data,
    }


def build_resource_statistics(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate statistics for a resource inventory."""
    if not resources:
        return {}

    valid_resources = [resource for resource in resources if isinstance(resource, dict)]
    sizes = [
        _resource_size(resource) for resource in valid_resources if _resource_size(resource) > 0
    ]
    entropies = [
        resource.get("entropy", 0)
        for resource in valid_resources
        if isinstance(resource.get("entropy", 0), int | float) and resource.get("entropy", 0) > 0
    ]

    return {
        "total_resources": len(valid_resources),
        "total_size": sum(sizes),
        "average_size": sum(sizes) // len(sizes) if sizes else 0,
        "max_size": max(sizes) if sizes else 0,
        "min_size": min(sizes) if sizes else 0,
        "average_entropy": sum(entropies) / len(entropies) if entropies else 0,
        "max_entropy": max(entropies) if entropies else 0,
        "unique_types": len({_resource_type_name(resource) for resource in valid_resources}),
    }


def check_resource_entropy(resource: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag high-entropy non-icon resources."""
    if resource.get("entropy", 0) <= 7.5:
        return []
    type_name = _resource_type_name(resource)
    if type_name in ["RT_ICON", "RT_BITMAP"]:
        return []
    return [
        {
            "resource": _resource_name(resource),
            "reason": "High entropy (possibly encrypted/packed)",
            "entropy": resource["entropy"],
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
        suspicious.extend(check_resource_entropy(resource))
        suspicious.extend(check_resource_size(resource))
        suspicious.extend(check_resource_rcdata(resource))

        header_data = None
        type_name = _resource_type_name(resource)
        if type_name in ["RT_RCDATA", "UNKNOWN"]:
            if _resource_size(resource) > 1024 and _resource_offset(resource) > 0:
                header_data = header_reader(resource)
        suspicious.extend(check_resource_embedded_pe(resource, header_data))

    return suspicious
