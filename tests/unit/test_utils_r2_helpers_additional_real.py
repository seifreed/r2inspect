from __future__ import annotations

from r2inspect.utils import r2_helpers


class _TextR2:
    def cmd(self, _command: str) -> str:
        return ""


class _HeadersR2:
    def get_headers_json(self) -> dict[str, int]:
        return {"name": "Signature", "value": 0x4550}

    def cmd(self, _command: str) -> str:
        return "IMAGE_FILE_HEADERS\nNumberOfSections: 5\n"


def test_validate_and_clean_r2_data_edges() -> None:
    assert r2_helpers.validate_r2_data({"a": 1}, "dict") == {"a": 1}
    assert r2_helpers.validate_r2_data([], "list") == []
    assert r2_helpers.validate_r2_data("x", "other") == "x"

    assert r2_helpers._validate_dict_data([1]) == {}
    assert r2_helpers._validate_list_data({"a": 1}) == []
    cleaned = r2_helpers._clean_list_items([{"name": "a&nbsp;"}, "bad"])
    assert cleaned[0]["name"] == "a "


def test_parse_pe_header_text_and_key_value_edges() -> None:
    assert r2_helpers.parse_pe_header_text(_TextR2()) is None

    class _CustomTextR2:
        def cmd(self, _command: str) -> str:
            return (
                "IMAGE_NT_HEADERS\n"
                "IMAGE_FILE_HEADERS\n"
                "NumberOfSections: 5\n"
                "\n"
                "IMAGE_OPTIONAL_HEADERS\n"
                "ImageBase: 0xZZ\n"
            )

    parsed = r2_helpers.parse_pe_header_text(_CustomTextR2())
    assert parsed is not None
    assert parsed["file_header"]["NumberOfSections"] == "5"
    assert parsed["optional_header"]["ImageBase"] == "0xZZ"


def test_get_pe_headers_fallback_and_non_dict_items() -> None:
    class _ListHeadersR2:
        def get_headers_json(self):
            return ["bad", {"name": "Signature", "value": 0x4550}]

        def cmd(self, _command: str) -> str:
            return "IMAGE_FILE_HEADERS\nSignature: 0x4550\n"

    result = r2_helpers.get_pe_headers(_ListHeadersR2())
    assert result is not None
    assert result["file_header"]["Signature"] == 0x4550

    fallback = r2_helpers.get_pe_headers(_HeadersR2())
    assert fallback is not None
    assert fallback["file_header"]["NumberOfSections"] == "5"


def test_get_elf_headers_and_helpers() -> None:
    class _ElfTextR2:
        def cmd(self, _command: str) -> str:
            return "Type: LOAD\nFlags: R\nOffset: 0x0\n"

    headers = r2_helpers.get_elf_headers(_ElfTextR2())
    assert headers

    class _HeadersNone:
        def get_headers_json(self):
            return None

    class _HeadersDict:
        def get_headers_json(self):
            return {"name": "x"}

    class _HeadersList:
        def get_headers_json(self):
            return [{"name": "x"}]

    class _HeadersOther:
        def get_headers_json(self):
            return "bad"

    assert r2_helpers._get_headers_json(_HeadersNone()) is None
    assert r2_helpers._get_headers_json(_HeadersDict()) == [{"name": "x"}]
    assert r2_helpers._get_headers_json(_HeadersList()) == [{"name": "x"}]
    assert r2_helpers._get_headers_json(_HeadersOther()) is None

    parsed = r2_helpers._parse_elf_headers_text("Type: LOAD\nBad Line\nFlags: R\n")
    assert any("type" in entry for entry in parsed)


def test_get_macho_headers_paths() -> None:
    class _MachoHeadersR2:
        def get_headers_json(self):
            return {"name": "cmd"}

    assert r2_helpers.get_macho_headers(_MachoHeadersR2()) == [{"name": "cmd"}]

    class _MachoTextR2:
        def cmd(self, _command: str) -> str:
            return ""

    assert r2_helpers.get_macho_headers(_MachoTextR2()) == []
