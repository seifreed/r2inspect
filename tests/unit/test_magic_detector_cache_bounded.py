from __future__ import annotations

from pathlib import Path

from r2inspect.infrastructure.magic_detector import MagicByteDetector


def test_cache_is_bounded(tmp_path: Path):
    """The detection cache must not grow without bound across many files.

    The module-level ``global_detector`` is process-global and is hit once
    per analyzed file by the pipeline; an unbounded cache there leaks memory
    over a long batch run.
    """
    detector = MagicByteDetector()
    overshoot = detector.CACHE_MAX_ENTRIES + 50
    for index in range(overshoot):
        sample = tmp_path / f"sample_{index}.bin"
        sample.write_bytes(b"MZ" + index.to_bytes(4, "little") + b"\x00" * 100)
        detector.detect_file_type(str(sample))

    assert len(detector.cache) <= detector.CACHE_MAX_ENTRIES
