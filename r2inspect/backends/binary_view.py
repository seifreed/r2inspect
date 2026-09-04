"""Bounds-checked access to an mmap-backed binary."""

from __future__ import annotations

import struct
from typing import Any


class BinaryView:
    def __init__(self, data: Any, *, base: int = 0, size: int | None = None) -> None:
        self.data = data
        self.base = base
        self.size = len(data) - base if size is None else size
        if base < 0 or self.size < 0 or base + self.size > len(data):
            raise ValueError("binary view is outside the file")

    def unpack(self, fmt: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        self._check(offset, size)
        return struct.unpack_from(fmt, self.data, self.base + offset)

    def read(self, offset: int, size: int) -> bytes:
        self._check(offset, size)
        return bytes(self.data[self.base + offset : self.base + offset + size])

    def cstring(self, offset: int, *, limit: int = 4096) -> str:
        self._check(offset, 1)
        raw = self.read(offset, min(limit, self.size - offset))
        return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")

    def subview(self, offset: int, size: int) -> BinaryView:
        self._check(offset, size)
        return BinaryView(self.data, base=self.base + offset, size=size)

    def _check(self, offset: int, size: int) -> None:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError(f"binary read outside file at {offset:#x} ({size} bytes)")


__all__ = ["BinaryView"]
