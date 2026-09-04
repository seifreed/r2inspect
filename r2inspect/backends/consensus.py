"""Run two backends and expose disagreements as first-class results."""

from __future__ import annotations

from typing import Any, Literal, TypedDict


from ..interfaces import BinaryInspector


class BackendDisagreement(TypedDict):
    field: str
    left_backend: str
    right_backend: str
    left: Any
    right: Any
    severity: Literal["warning"]
    status: Literal["backend_disagreement"]


_MISSING = object()


def _path(data: dict[str, Any], *parts: str) -> Any:
    value: Any = data
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _pick(data: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = _path(data, *path)
        if value is not _MISSING:
            return value
    return _MISSING


def _named_items(value: Any) -> tuple[str, ...] | object:
    if not isinstance(value, list):
        return _MISSING
    names = []
    for item in value:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            library = item.get("library") or item.get("libname") or ""
            name = item.get("name") or item.get("symbol") or item.get("ordinal")
            names.append(f"{library}!{name}" if library else str(name))
    return tuple(sorted(names))


def _architecture(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    normalized = value.lower().replace("-", "_")
    return {"amd_64": "x86_64", "amd64": "x86_64"}.get(normalized, normalized)


def _overlay(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {
        "offset": value.get("offset", value.get("overlay_offset")),
        "size": value.get("size", value.get("overlay_size")),
    }


def _consensus_view(result: dict[str, Any]) -> dict[str, Any]:
    view: dict[str, Any] = {}
    aliases = {
        "format.common.format": (
            ("format_detection", "file_format"),
            ("file_info", "file_type"),
        ),
        "format.common.architecture": (
            ("file_info", "architecture"),
            ("pe_info", "architecture"),
            ("elf_info", "architecture"),
            ("macho_info", "architecture"),
        ),
        "format.common.bits": (
            ("file_info", "bits"),
            ("pe_info", "bits"),
            ("elf_info", "bits"),
            ("macho_info", "bits"),
        ),
        "format.common.endianness": (
            ("file_info", "endian"),
            ("pe_info", "endian"),
            ("elf_info", "endian"),
            ("macho_info", "endian"),
        ),
    }
    for field, paths in aliases.items():
        value = _pick(result, *paths)
        if value is not _MISSING:
            view[field] = _architecture(value) if field.endswith("architecture") else value

    format_name = str(view.get("format.common.format", "")).lower()
    family = next(
        (name for name in ("pe", "elf", "macho") if format_name.startswith(name)),
        "common",
    )
    prefix = f"format.{family}"
    for name in ("entry_point", "image_base", "build_id", "uuid"):
        value = _pick(result, (name,), ("file_info", name), (f"{family}_info", name))
        if value is not _MISSING:
            view[f"{prefix}.{name}"] = value
    overlay = _pick(result, ("overlay",), (f"{family}_info", "overlay"))
    if overlay is not _MISSING:
        view[f"{prefix}.overlay"] = _overlay(overlay)
    signature = _pick(
        result,
        ("signature_status",),
        (f"{family}_info", "signature_status"),
        (f"{family}_info", "authenticode", "has_signature"),
        ("authenticode", "has_signature"),
    )
    if signature is not _MISSING:
        view[f"{prefix}.signature_status"] = (
            ("present" if signature else "absent") if isinstance(signature, bool) else signature
        )

    sections = _pick(result, ("sections",), (f"{family}_info", "sections"))
    if isinstance(sections, list):
        view[f"{prefix}.section_count"] = len(sections)
        boundaries = [
            (
                str(section.get("name", "")),
                section.get("vaddr", section.get("virtual_address")),
                section.get("size", section.get("virtual_size")),
            )
            for section in sections
            if isinstance(section, dict)
        ]
        view[f"{prefix}.section_boundaries"] = tuple(sorted(boundaries, key=repr))
    for name in ("imports", "exports"):
        value = _named_items(_pick(result, (name,), (f"{family}_info", name)))
        if value is not _MISSING:
            view[f"{prefix}.{name}"] = value
    security = _pick(result, (f"{family}_info", "security_features"), ("security",))
    if isinstance(security, dict):
        for name, value in security.items():
            view[f"security.{name}"] = value
    return view


def compare_results(
    left: dict[str, Any],
    right: dict[str, Any],
    left_backend: str = "left",
    right_backend: str = "right",
) -> list[BackendDisagreement]:
    left_view = _consensus_view(left)
    right_view = _consensus_view(right)
    disagreements: list[BackendDisagreement] = []
    for field in sorted(set(left_view) | set(right_view)):
        left_value = left_view.get(field)
        right_value = right_view.get(field)
        if left_value != right_value:
            disagreements.append(
                {
                    "field": field,
                    "left_backend": left_backend,
                    "right_backend": right_backend,
                    "left": left_value,
                    "right": right_value,
                    "severity": "warning",
                    "status": "backend_disagreement",
                }
            )
    return disagreements


class ConsensusInspector:
    def __init__(
        self, left: BinaryInspector, right: BinaryInspector, left_name: str, right_name: str
    ) -> None:
        self.left = left
        self.right = right
        self.left_name = left_name
        self.right_name = right_name

    def analyze(self, **options: Any) -> dict[str, Any]:
        left_result = self.left.analyze(**options)
        right_result = self.right.analyze(**options)
        disagreements = compare_results(left_result, right_result, self.left_name, self.right_name)
        result = dict(left_result)
        result["backend"] = "consensus"
        result["backend_results"] = {
            self.left_name: left_result,
            self.right_name: right_result,
        }
        result["backend_disagreements"] = disagreements
        if disagreements:
            result["warnings"] = ["independent backends disagree"]
        return result

    def close(self) -> None:
        for backend in (self.left, self.right):
            close = getattr(backend, "close", None)
            if callable(close):
                close()

    def __enter__(self) -> ConsensusInspector:
        return self

    def __exit__(self, *_args: Any) -> Literal[False]:
        self.close()
        return False


__all__ = ["BackendDisagreement", "ConsensusInspector", "compare_results"]
