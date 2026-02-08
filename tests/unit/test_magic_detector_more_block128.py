from __future__ import annotations

from pathlib import Path

from r2inspect.utils.magic_detector import MagicByteDetector


def test_magic_detector_docx_like_file(tmp_path: Path):
    docx = tmp_path / "sample.docx"
    content = b"PK\x03\x04" + b"word/" + b"[Content_Types].xml" + b"office"
    docx.write_bytes(content)

    detector = MagicByteDetector()
    result = detector.detect_file_type(str(docx))

    assert result["format_category"] == "Document"
    assert result["is_document"] is True
    assert result["confidence"] >= 0.6


def test_magic_detector_fallback_script(tmp_path: Path):
    script = tmp_path / "test.ps1"
    script.write_text("#!/bin/bash\necho hi")

    detector = MagicByteDetector()
    result = detector.detect_file_type(str(script))

    assert result["format_category"] in {"Executable", "Script"}
    assert result["potential_threat"] is True
