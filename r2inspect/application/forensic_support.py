"""Serialization, hashing, and evidence helpers for forensic bundles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any, cast

_SNIPPET_SIZE = 64
_MAX_SNIPPETS = 256
_SECRET_MARKERS = ("api_key", "apikey", "password", "secret", "token")


def json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    for method_name in ("model_dump", "to_dict"):
        method = getattr(value, method_name, None)
        if callable(method):
            return method()
    if isinstance(value, Path):
        return str(value)
    return repr(value)


def json_text(value: Any) -> str:
    return json.dumps(value, default=json_default, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_artifact(directory: Path, name: str, content: str) -> dict[str, Any]:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return {"name": name, "size": path.stat().st_size, "sha256": sha256_file(path)}


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[redacted]"
                if any(marker in str(key).lower() for marker in _SECRET_MARKERS)
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    return value


def effective_configuration(config: Any, options: dict[str, Any]) -> dict[str, Any]:
    to_dict = getattr(config, "to_dict", None)
    runtime = to_dict() if callable(to_dict) else {}
    return cast(dict[str, Any], redact({"analysis_options": options, "runtime": runtime}))


def collect_messages(value: Any, path: str = "$") -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key.lower() in {"error", "errors", "warning", "warnings"} and item not in (
                None,
                "",
                [],
                {},
            ):
                messages.append({"path": child_path, "value": item})
            messages.extend(collect_messages(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            messages.extend(collect_messages(item, f"{path}[{index}]"))
    return messages


def finding_locations(value: Any, path: str = "$") -> list[tuple[str, dict[str, Any]]]:
    locations: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        reference = str(
            value.get("finding_id") or value.get("rule_id") or value.get("title") or path
        )
        raw_locations = value.get("locations")
        if isinstance(raw_locations, list):
            locations.extend(
                (reference, location) for location in raw_locations if isinstance(location, dict)
            )
        for key, item in value.items():
            if key != "locations":
                locations.extend(finding_locations(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            locations.extend(finding_locations(item, f"{path}[{index}]"))
    return locations


def evidence_snippets(
    sample_path: Path, adapter: Any, results: dict[str, Any]
) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None, int | None]] = set()
    with sample_path.open("rb") as sample:
        for reference, location in finding_locations(results):
            offset = location.get("offset")
            virtual_address = location.get("virtual_address")
            key = (
                reference,
                offset if isinstance(offset, int) else None,
                virtual_address if isinstance(virtual_address, int) else None,
            )
            if key in seen or len(snippets) >= _MAX_SNIPPETS:
                continue
            seen.add(key)
            data = b""
            try:
                if isinstance(offset, int) and offset >= 0:
                    sample.seek(offset)
                    data = sample.read(_SNIPPET_SIZE)
                elif isinstance(virtual_address, int) and virtual_address >= 0:
                    read_bytes = getattr(adapter, "read_bytes", None)
                    if callable(read_bytes):
                        candidate = read_bytes(virtual_address, _SNIPPET_SIZE)
                        if isinstance(candidate, bytes | bytearray):
                            data = bytes(candidate)
            except (OSError, ValueError, OverflowError):
                continue
            if data:
                snippets.append(
                    {
                        "finding": reference,
                        "location": location,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes_hex": data.hex(),
                    }
                )
    return snippets


__all__ = [
    "collect_messages",
    "effective_configuration",
    "evidence_snippets",
    "json_text",
    "sha256_file",
    "write_artifact",
]
