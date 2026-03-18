from __future__ import annotations

from r2inspect.domain.services.rich_header import (
    COMPILER_PRODUCTS,
    build_rich_header_result,
    calculate_richpe_hash,
    decode_rich_header,
    get_compiler_description,
    parse_clear_data_entries,
    parse_compiler_entries,
    validate_decoded_entries,
)


def test_parse_clear_data_entries_and_compilers() -> None:
    clear_data = (
        (0x0008 | (123 << 16)).to_bytes(4, "little")
        + (5).to_bytes(4, "little")
        + (0x0009 | (124 << 16)).to_bytes(4, "little")
        + (7).to_bytes(4, "little")
    )

    entries = parse_clear_data_entries(clear_data)
    compilers = parse_compiler_entries(entries)

    assert len(entries) == 2
    assert compilers[0]["compiler_name"] == COMPILER_PRODUCTS[0x0008]


def test_get_compiler_description() -> None:
    assert "Microsoft C/C++ Compiler" in get_compiler_description("Utc1900_C", 123)


def test_decode_validate_and_build_rich_result() -> None:
    xor_key = 0x12345678
    prodid = 0x0008
    count = 5
    encoded = (
        b"DanS"
        + ((prodid ^ xor_key).to_bytes(4, "little"))
        + ((count ^ xor_key).to_bytes(4, "little"))
    )

    decoded = decode_rich_header(encoded, xor_key)
    assert validate_decoded_entries(decoded) is True

    result = build_rich_header_result(decoded, xor_key)
    assert result["xor_key"] == xor_key
    assert result["entries"]


def test_calculate_richpe_hash() -> None:
    hash_from_entries = calculate_richpe_hash({"entries": [{"prodid": 1, "count": 2}]})
    hash_from_bytes = calculate_richpe_hash(
        {"clear_data_bytes": b"\x01\x00\x00\x00\x02\x00\x00\x00"}
    )

    assert hash_from_entries
    assert hash_from_bytes
