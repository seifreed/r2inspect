from __future__ import annotations

import struct

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


def test_rich_header_decode_and_validate():
    analyzer = RichHeaderAnalyzer(r2_instance=None, filepath="sample")

    xor_key = 0x1
    prodid = 0x10
    count = 5
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    encoded = b"DanS" + encoded_entry + b"Rich"

    entries = analyzer._decode_rich_header(encoded, xor_key)
    assert len(entries) == 1
    assert entries[0]["prodid"] == prodid
    assert entries[0]["count"] == count

    assert analyzer._validate_decoded_entries(entries) is True
    result = analyzer._build_rich_header_result(entries, xor_key)
    assert result["xor_key"] == xor_key
    assert result["checksum"] == (prodid ^ count)
    assert result["entries"] == entries
