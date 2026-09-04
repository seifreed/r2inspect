"""Independent header backends used for cross-engine comparison."""

from __future__ import annotations

import hashlib
import mmap
from pathlib import Path
from typing import Any, Literal

from .binary_view import BinaryView
from .pe_core import parse_pe


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
        size = path.stat().st_size
        parse_error: str | None = None
        with path.open("rb") as stream:
            sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            if size:
                with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                    detected = _format(data[:4])
                    try:
                        parsed = (
                            parse_pe(BinaryView(data))
                            if self.backend == "pe-core" and detected == "PE"
                            else None
                        )
                    except ValueError as exc:
                        parsed, parse_error = None, str(exc)
            else:
                detected, parsed = "UNKNOWN", None
        expected = {"pe-core": "PE", "elf-core": "ELF", "macho-core": "MACHO"}.get(self.backend)
        result: dict[str, Any] = {
            "backend": self.backend,
            "file_info": {
                "path": str(path),
                "name": path.name,
                "size": size,
                "sha256": sha256,
                "file_type": detected,
            },
            "format_detection": {"file_format": detected, "backend": self.backend},
        }
        if parsed is not None:
            result["pe_info"] = parsed
            for field in ("architecture", "bits", "endian"):
                result["file_info"][field] = parsed[field]
            for field in ("sections", "imports", "exports"):
                result[field] = parsed[field]
            result["security"] = parsed["security_features"]
        if parse_error:
            result["error"] = f"invalid {detected} structure: {parse_error}"
            result["status"] = "failed"
        elif expected and detected not in {expected, "UNKNOWN"}:
            result["error"] = f"unsupported format for {self.backend}: {detected}"
            result["status"] = "unsupported"
        return result

    def close(self) -> None:
        return None

    def __enter__(self) -> CoreBackendInspector:
        return self

    def __exit__(self, *_args: Any) -> Literal[False]:
        self.close()
        return False


def build_core_backend(filename: str, *, backend: str, **_kwargs: Any) -> CoreBackendInspector:
    return CoreBackendInspector(filename, backend)


__all__ = ["CoreBackendInspector", "build_core_backend"]
