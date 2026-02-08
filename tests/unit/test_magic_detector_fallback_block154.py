from __future__ import annotations

from pathlib import Path

from r2inspect.utils.magic_detector import MagicByteDetector


def test_magic_detector_fallback_executable_extension(tmp_path: Path):
    exe = tmp_path / "sample.exe"
    exe.write_bytes(b"not a real exe")

    detector = MagicByteDetector()
    result = detector.detect_file_type(str(exe))

    assert result["format_category"] == "Executable"
    assert result["is_executable"] is True
    assert result["potential_threat"] is True
