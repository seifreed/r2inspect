from __future__ import annotations

import struct

from r2inspect.utils.magic_detector import MagicByteDetector


def test_magic_detector_validate_pe_format(tmp_path):
    # Create minimal PE-like file
    data = bytearray(b"MZ" + b"\x00" * 62)
    pe_offset = 0x40
    data[60:64] = struct.pack("<I", pe_offset)
    # ensure header large enough to include PE signature
    if len(data) < pe_offset + 4:
        data.extend(b"\x00" * (pe_offset + 4 - len(data)))
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    path = tmp_path / "sample.bin"
    path.write_bytes(data)

    detector = MagicByteDetector()
    with path.open("rb") as f:
        header = f.read(128)
        assert detector._validate_pe_format(header, f) >= 0.9

    # Invalid header
    with path.open("rb") as f:
        assert detector._validate_pe_format(b"ZZ" + b"\x00" * 62, f) == 0.0
