from __future__ import annotations

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


def test_rich_header_basic_helpers():
    analyzer = RichHeaderAnalyzer(r2_instance=None, filepath="sample")

    assert analyzer._offset_pair_valid(10, 20, 15) is True
    assert analyzer._offset_pair_valid(20, 10, 15) is False
    assert analyzer._offset_pair_valid(10, 30, 15) is False

    assert analyzer._validate_rich_size(9) is True
    assert analyzer._validate_rich_size(8) is False
    assert analyzer._validate_rich_size(513) is False

    data = b"aaaaRichbbbbRich"
    positions = analyzer._find_rich_positions(data)
    assert positions == [4]

    assert analyzer._is_valid_rich_key(b"Rich\x00\x00\x00\x00", 0) is False
    assert analyzer._is_valid_rich_key(b"Rich\x01\x00\x00\x00", 0) is True
