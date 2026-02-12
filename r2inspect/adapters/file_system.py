#!/usr/bin/env python3
"""Filesystem adapter for controlled IO access."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class FileSystemAdapter:
    """Provide a minimal filesystem access abstraction."""

    def read_bytes(self, path: str | Path, size: int | None = None, offset: int = 0) -> bytes:
        file_path = Path(path)
        with file_path.open("rb") as handle:
            if offset:
                handle.seek(offset)
            return handle.read() if size is None else handle.read(size)

    def read_text(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        errors: str = "ignore",
    ) -> str:
        file_path = Path(path)
        return file_path.read_text(encoding=encoding, errors=errors)

    def write_text(
        self,
        path: str | Path,
        data: str,
        *,
        encoding: str = "utf-8",
    ) -> None:
        file_path = Path(path)
        file_path.write_text(data, encoding=encoding)


default_file_system = FileSystemAdapter()
