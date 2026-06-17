"""Regression tests for bugs fixed in loop iteration 1.

1. ``decode_rich_header`` must emit ``product_id``/``build_number`` so the
   direct-file Rich checksum path actually folds entry contributions in
   (previously those keys were absent and every entry contributed 0).
2. ``detect_via_header_bytes`` must read only the header, not the whole file.
3. CSV cells beginning with a formula trigger character must be neutralized
   to prevent spreadsheet formula injection (CWE-1236).
"""

from __future__ import annotations

import struct

from r2inspect.cli.output_csv import CsvOutputFormatter
from r2inspect.cli.output_csv_fields import escape_csv_formula
from r2inspect.domain.services.rich_header import decode_rich_header
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.pipeline.pipeline_runtime_common import detect_via_header_bytes


def test_decode_rich_header_entries_feed_into_checksum() -> None:
    xor_key = 0x12345678
    prodid = 0x00930001
    count = 7
    encoded = b"DanS" + struct.pack("<II", prodid ^ xor_key, count ^ xor_key)
    entries = decode_rich_header(encoded, xor_key)

    assert entries
    assert entries[0]["product_id"] == 0x0001
    assert entries[0]["build_number"] == 0x0093

    analyzer = RichHeaderAnalyzer(adapter=None, filepath=None)
    data = b"MZ" + b"\x00" * 62
    dos_only = analyzer._calculate_rich_checksum(data, 0x40, [])
    with_entries = analyzer._calculate_rich_checksum(data, 0x40, entries)

    # The decoded entries must actually change the checksum; before the fix the
    # missing product_id/build_number keys made the entry term collapse to 0.
    assert with_entries != dos_only


def test_detect_via_header_bytes_does_not_read_whole_file(tmp_path) -> None:
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"MZ" + b"\x00" * (5 * 1024 * 1024))
    assert detect_via_header_bytes(str(sample)) == "PE"

    elf = tmp_path / "elf.bin"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 16)
    assert detect_via_header_bytes(str(elf)) == "ELF"

    missing = tmp_path / "nope.bin"
    assert detect_via_header_bytes(str(missing)) is None


def test_escape_csv_formula_neutralizes_dangerous_prefixes() -> None:
    assert escape_csv_formula("=cmd|'/c calc'!A1") == "'=cmd|'/c calc'!A1"
    assert escape_csv_formula("+1") == "'+1"
    assert escape_csv_formula("-2") == "'-2"
    assert escape_csv_formula("@x") == "'@x"
    assert escape_csv_formula("\tx") == "'\tx"
    assert escape_csv_formula("normal.exe") == "normal.exe"
    assert escape_csv_formula(42) == 42


def test_csv_output_escapes_formula_in_filename() -> None:
    results = {"file_info": {"name": "=cmd|'/c calc'!A1.exe", "size": 10}}
    csv_text = CsvOutputFormatter(results).to_csv()
    assert "'=cmd|'/c calc'!A1.exe" in csv_text
    assert ",=cmd|" not in csv_text
