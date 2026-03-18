from __future__ import annotations

from pathlib import Path


def write_minimal_pe_file(path: Path) -> Path:
    data = bytearray(128)
    data[0:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    path.write_bytes(data)
    return path


class DummyRateLimiter:
    def __init__(self, stats: dict[str, float] | None = None) -> None:
        self._stats = stats or {
            "success_rate": 1.0,
            "avg_wait_time": 0.0,
            "current_rate": 1.0,
        }

    def get_stats(self) -> dict[str, float]:
        return dict(self._stats)
