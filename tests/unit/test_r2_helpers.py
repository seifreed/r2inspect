import r2inspect.infrastructure.r2_helpers as r2_helpers
from r2inspect.testing.fake_r2 import FakeR2


def test_validate_r2_data_dict_and_list():
    assert r2_helpers.validate_r2_data({"a": 1}, "dict") == {"a": 1}
    assert r2_helpers.validate_r2_data([{"name": "a"}], "list") == [{"name": "a"}]
    assert r2_helpers.validate_r2_data("x", "dict") == {}
    assert r2_helpers.validate_r2_data("x", "list") == []


def test_clean_list_items_html_entities():
    data = [{"name": "A&nbsp;B &amp; C"}, "bad"]
    cleaned = r2_helpers.validate_r2_data(data, "list")
    assert cleaned == [{"name": "A B & C"}]


def test_parse_pe_header_text():
    # Real r2 `iHH` emits the IMAGE_* section layout this parser reads; plain
    # `ih` is a columnar table with no section markers or colons. The parser
    # must issue iHH and ignore ih, otherwise every header dict comes back empty.
    ihh = (
        "PE file header:\n"
        "IMAGE_NT_HEADERS\n"
        "  Signature : 0x4550\n"
        "IMAGE_FILE_HEADERS\n"
        "  NumberOfSections : 0x12\n"
        "IMAGE_OPTIONAL_HEADERS\n"
        "  ImageBase : 0x140000000\n"
    )
    ih = "0x00000080 0x00000080 0x00004550 Signature\n0x00000086 0x00000086 0x12 NumberOfSections\n"
    r2 = FakeR2(cmd_map={"iHH": ihh, "ih": ih})
    parsed = r2_helpers.parse_pe_header_text(r2)
    assert parsed is not None
    assert parsed["nt_headers"]["Signature"] == 0x4550
    assert parsed["file_header"]["NumberOfSections"] == 0x12
    assert parsed["optional_header"]["ImageBase"] == 0x140000000


def test_get_pe_headers_from_json():
    headers = [
        {"name": "Signature", "value": 0x4550},
        {"name": "ImageBase", "value": 0x400000},
    ]
    r2 = FakeR2(cmdj_map={"ihj": headers})
    parsed = r2_helpers.get_pe_headers(r2)
    assert parsed is not None
    assert parsed["file_header"]["Signature"] == 0x4550
    assert parsed["optional_header"]["ImageBase"] == 0x400000


def test_get_elf_headers_json_dict():
    r2 = FakeR2(cmdj_map={"ihj": {"type": "LOAD"}})
    headers = r2_helpers.get_elf_headers(r2)
    assert headers == [{"type": "LOAD"}]


def test_get_elf_headers_text_fallback():
    text = "Type: LOAD\nFlags: R\nOffset: 0x10\n"
    r2 = FakeR2(cmdj_map={"ihj": None}, cmd_map={"ih": text})
    headers = r2_helpers.get_elf_headers(r2)
    assert {"type": "LOAD"} in headers
