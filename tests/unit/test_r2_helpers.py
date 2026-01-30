from r2inspect.utils import r2_helpers


class FakeR2:
    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command)

    def cmd(self, command):
        return self.cmd_map.get(command, "")


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
    text = """
    IMAGE_NT_HEADERS
    Signature: 0x4550
    IMAGE_FILE_HEADERS
    NumberOfSections: 5
    IMAGE_OPTIONAL_HEADERS
    ImageBase: 0x400000
    """
    r2 = FakeR2(cmd_map={"ih": text})
    parsed = r2_helpers.parse_pe_header_text(r2)
    assert parsed is not None
    assert parsed["file_header"]["NumberOfSections"] == "5"
    assert parsed["optional_header"]["ImageBase"] == 0x400000


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
