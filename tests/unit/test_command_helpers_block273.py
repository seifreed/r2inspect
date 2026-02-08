from __future__ import annotations

import pytest

from r2inspect.utils import command_helpers


class DummyAdapter:
    def __init__(self) -> None:
        self.called = []

    def search_hex_json(self, pattern: str):
        self.called.append(("search_hex_json", pattern))
        return {"hits": 1}

    def search_text(self, pattern: str):
        self.called.append(("search_text", pattern))
        return [pattern]

    def search_hex(self, pattern: str):
        self.called.append(("search_hex", pattern))
        return "ok"

    def get_strings_filtered(self, command: str):
        self.called.append(("get_strings_filtered", command))
        return ["s"]

    def get_functions_at(self, address: int):
        self.called.append(("get_functions_at", address))
        return [{"addr": address}]

    def get_functions(self):
        self.called.append(("get_functions", None))
        return [{"addr": 0}]

    def get_function_info(self, address: int):
        self.called.append(("get_function_info", address))
        return {"addr": address}

    def get_disasm(self, address: int | None = None, size: int | None = None):
        self.called.append(("get_disasm", address, size))
        return [{"op": "nop"}]

    def get_disasm_text(self, address: int | None = None, size: int | None = None):
        self.called.append(("get_disasm_text", address, size))
        return "nop"

    def get_cfg(self, address: int | None = None):
        self.called.append(("get_cfg", address))
        return {"cfg": True}

    def read_bytes_list(self, address: int, size: int):
        self.called.append(("read_bytes_list", address, size))
        return [1, 2]

    def read_bytes(self, address: int, size: int):
        self.called.append(("read_bytes", address, size))
        return b"\x01\x02"


@pytest.mark.unit
def test_command_helpers_parsing_and_search() -> None:
    base, addr = command_helpers._parse_address("pdj 4 @ 0x10")
    assert base == "pdj 4"
    assert addr == 0x10

    assert command_helpers._parse_address("pdj 4 @")[1] is None
    assert command_helpers._parse_address("pdj 4")[1] is None

    assert command_helpers._parse_size("pdj 4") == 4
    assert command_helpers._parse_size("pdj") is None
    assert command_helpers._parse_size("pdj zz") is None

    adapter = DummyAdapter()
    assert command_helpers._handle_search(adapter, "/xj ff") == {"hits": 1}
    assert command_helpers._handle_search(adapter, "/c test") == ["test"]
    assert command_helpers._handle_search(adapter, "/x aa") == "ok"


@pytest.mark.unit
def test_command_helpers_simple_and_disasm_and_bytes() -> None:
    adapter = DummyAdapter()
    assert command_helpers._handle_simple(adapter, "iz~foo", "iz~foo", None) == ["s"]
    assert command_helpers._handle_simple(adapter, "aflj", "aflj @ 0x10", 0x10)[0]["addr"] == 0x10
    assert command_helpers._handle_simple(adapter, "aflj", "aflj", None)[0]["addr"] == 0
    assert command_helpers._handle_simple(adapter, "afij", "afij @ 0x10", 0x10)["addr"] == 0x10

    assert command_helpers._handle_disasm(adapter, "pdfj", 0x20) == [{"op": "nop"}]
    assert command_helpers._handle_disasm(adapter, "pdj 4", 0x20) == [{"op": "nop"}]
    assert command_helpers._handle_disasm(adapter, "pi 8", 0x20) == "nop"
    assert command_helpers._handle_disasm(adapter, "agj", 0x20) == {"cfg": True}

    assert command_helpers._handle_bytes(adapter, "p8j 2", 0x10) == [1, 2]
    assert command_helpers._handle_bytes(adapter, "p8 2", 0x10) == "0102"
    assert command_helpers._handle_bytes(adapter, "pxj 2", 0x10) == [1, 2]
    assert command_helpers._handle_bytes(adapter, "p8 2", None) is None


@pytest.mark.unit
def test_cmd_cmdj_and_cmd_list_helpers() -> None:
    adapter = DummyAdapter()
    assert command_helpers.cmd(adapter, None, "pi 2 @ 0x10") == "nop"
    assert command_helpers.cmdj(adapter, None, "/xj ff", default={}) == {"hits": 1}
    assert command_helpers.cmdj(adapter, None, "unknown", default={"d": 1}) == {"d": 1}
    assert command_helpers.cmd_list(adapter, None, "/c ok") == ["ok"]
