"""Independent header backends used for cross-engine comparison."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def _format(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }:
        return "MACHO"
    return "UNKNOWN"


class CoreBackendInspector:
    """Small dependency-free backend contract for independent consensus data."""

    def __init__(self, filename: str, backend: str) -> None:
        self.filename = filename
        self.backend = backend

    def analyze(self, **_options: Any) -> dict[str, Any]:
        path = Path(self.filename)
        data = path.read_bytes()
        detected = _format(data)
        expected = {"pe-core": "PE", "elf-core": "ELF", "macho-core": "MACHO"}.get(self.backend)
        result: dict[str, Any] = {
            "backend": self.backend,
            "file_info": {
                "path": str(path),
                "name": path.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "file_type": detected,
            },
            "format_detection": {"file_format": detected, "backend": self.backend},
        }
        if expected and detected not in {expected, "UNKNOWN"}:
            result["error"] = f"unsupported format for {self.backend}: {detected}"
            result["status"] = "unsupported"
        return result

    def close(self) -> None:
        return None

    def __enter__(self) -> CoreBackendInspector:
        return self

    def __exit__(self, *_args: Any) -> bool:
        self.close()
        return False


def build_core_backend(filename: str, *, backend: str, **_kwargs: Any) -> CoreBackendInspector:
    return CoreBackendInspector(filename, backend)


__all__ = ["CoreBackendInspector", "build_core_backend"]
