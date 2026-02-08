from __future__ import annotations

from r2inspect.utils.magic_detector import MagicByteDetector


def test_magic_detector_category_helpers():
    detector = MagicByteDetector()

    assert detector._get_format_category("PE32") == "Executable"
    assert detector._get_format_category("ZIP") == "Archive"
    assert detector._get_format_category("PDF") == "Document"
    assert detector._get_format_category("SWF") == "Bytecode"

    assert detector._is_executable_format("PE32") is True
    assert detector._is_archive_format("ZIP") is True
    assert detector._is_document_format("PDF") is True
    assert detector._is_potential_threat("PE32") is True
