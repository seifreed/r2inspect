from __future__ import annotations

from pathlib import Path

from r2inspect.utils.magic_detector import MagicByteDetector


def test_magic_detector_cache(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)

    detector = MagicByteDetector()
    first = detector.detect_file_type(str(sample))
    second = detector.detect_file_type(str(sample))

    assert first is second
    assert first["file_size"] == sample.stat().st_size
