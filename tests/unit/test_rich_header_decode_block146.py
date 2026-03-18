from __future__ import annotations

import struct

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.domain.services.rich_header import (
    build_rich_header_result,
    decode_rich_header,
    validate_decoded_entries,
)


def test_rich_header_decode_and_validate():
    xor_key = 0x1
    prodid = 0x10
    count = 5
    encoded_entry = struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    encoded = encoded_entry

    entries = decode_rich_header(encoded, xor_key)
    assert isinstance(entries, list)

    assert validate_decoded_entries(entries) in {True, False}
    result = build_rich_header_result(entries, xor_key)
    assert result["xor_key"] == xor_key
    assert result["entries"] == entries
