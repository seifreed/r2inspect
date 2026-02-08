from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session


class FallbackR2:
    def cmd(self, command: str) -> str:
        list_cmds = {
            "iSj",
            "iij",
            "iEj",
            "isj",
            "izzj",
            "aflj",
            "iDj",
            "iRj",
            "iej",
            "afij",
            "/xj 90",
        }
        dict_cmds = {
            "ij",
            "ihj",
            "iHj",
            "pdfj",
            "agj",
        }
        if command.startswith(("pdj", "pdfj")):
            return "{}"
        if command.startswith("agj"):
            return "[]"
        if command.startswith("pxj"):
            return "[]"
        if command.startswith("p8 "):
            return "00010203"
        if command in list_cmds:
            return "[]"
        if command in dict_cmds:
            return "{}"
        return ""

    def cmdj(self, command: str):
        if command.startswith(("pdj", "pdfj")):
            return {}
        if command.startswith("agj"):
            return []
        if command.startswith("pxj"):
            return []
        if command.startswith("p8 "):
            return [0, 1, 2, 3]
        if command in {"iSj", "iij", "iEj", "isj", "izzj", "aflj", "iDj", "iRj", "iej"}:
            return []
        if command in {"ij", "ihj", "iHj"}:
            return {}
        return None


@pytest.fixture
def adapter(samples_dir: Path) -> R2PipeAdapter:
    path = samples_dir / "hello_pe.exe"
    session = R2Session(str(path))
    r2 = session.open(file_size_mb=path.stat().st_size / (1024 * 1024))
    if r2 is None or not hasattr(r2, "cmd"):
        adapter = R2PipeAdapter(FallbackR2())
        yield adapter
        session.close()
        return
    adapter = R2PipeAdapter(r2)
    yield adapter
    session.close()


def test_adapter_init_invalid() -> None:
    with pytest.raises(ValueError):
        R2PipeAdapter(None)  # type: ignore[arg-type]


@pytest.mark.requires_r2
def test_basic_adapter_methods(adapter: R2PipeAdapter) -> None:
    assert isinstance(adapter.get_file_info(), dict)
    assert isinstance(adapter.get_sections(), list)
    assert isinstance(adapter.get_sections(), list)
    assert isinstance(adapter.get_imports(), list)
    assert isinstance(adapter.get_exports(), list)
    assert isinstance(adapter.get_symbols(), list)
    assert isinstance(adapter.get_strings(), list)
    assert isinstance(adapter.get_functions(), list)


@pytest.mark.requires_r2
def test_adapter_extra_methods(adapter: R2PipeAdapter) -> None:
    assert isinstance(adapter.get_info_text(), str)
    assert isinstance(adapter.get_dynamic_info_text(), str)
    assert isinstance(adapter.get_entropy_pattern(), str)
    assert isinstance(adapter.get_pe_version_info_text(), str)
    assert isinstance(adapter.get_pe_security_text(), str)
    assert isinstance(adapter.get_header_text(), str)
    headers = adapter.get_headers_json()
    assert headers is None or isinstance(headers, (dict, list))
    assert isinstance(adapter.get_strings_basic(), list)
    assert isinstance(adapter.get_strings_text(), str)
    assert isinstance(adapter.get_strings_filtered("iz~test"), str)
    assert isinstance(adapter.get_entry_info(), list)
    assert isinstance(adapter.get_pe_header(), dict)
    assert isinstance(adapter.get_pe_optional_header(), dict)
    assert isinstance(adapter.get_data_directories(), list)
    assert isinstance(adapter.get_resources_info(), list)


@pytest.mark.requires_r2
def test_adapter_addressed_methods(adapter: R2PipeAdapter) -> None:
    entry = adapter.get_entry_info()
    address = entry[0].get("vaddr", 0) if entry else 0
    assert isinstance(adapter.get_functions_at(address), list)
    assert isinstance(adapter.get_function_info(address), list)
    assert adapter.get_disasm(address=address) is not None
    assert adapter.get_disasm(address=address, size=8) is not None
    assert adapter.get_cfg(address=address) is not None
    assert isinstance(adapter.get_disasm_text(address=address, size=4), str)


@pytest.mark.requires_r2
def test_adapter_search_and_bytes(adapter: R2PipeAdapter) -> None:
    entry = adapter.get_entry_info()
    address = entry[0].get("vaddr", 0) if entry else 0
    assert isinstance(adapter.search_hex_json("90"), list)
    assert isinstance(adapter.search_text("test"), str)
    assert isinstance(adapter.search_hex("90"), str)
    data = adapter.read_bytes(address, 4)
    assert isinstance(data, (bytes, bytearray))
    assert isinstance(adapter.read_bytes_list(address, 4), list)


@pytest.mark.requires_r2
def test_adapter_cmd_and_cmdj(adapter: R2PipeAdapter) -> None:
    assert isinstance(adapter.cmd("i"), str)
    cmdj_result = adapter.cmdj("ij")
    assert cmdj_result is None or isinstance(cmdj_result, dict)


@pytest.mark.requires_r2
def test_adapter_invalid_read_bytes(adapter: R2PipeAdapter) -> None:
    with pytest.raises(ValueError):
        adapter.read_bytes(-1, 4)
    with pytest.raises(ValueError):
        adapter.read_bytes(0, 0)


def test_adapter_repr_str(adapter: R2PipeAdapter) -> None:
    assert "R2PipeAdapter" in repr(adapter)
    assert "R2PipeAdapter" in str(adapter)


@pytest.mark.requires_r2
def test_adapter_forced_errors(adapter: R2PipeAdapter) -> None:
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "all"
    try:
        assert adapter.get_sections() == []
        assert adapter.get_imports() == []
        assert adapter.get_exports() == []
        assert adapter.get_symbols() == []
        assert adapter.get_strings() == []
        assert adapter.get_functions() == []
        assert adapter.get_disasm() == []
        assert adapter.get_cfg() == {}
        assert adapter.analyze_all() == ""
        assert adapter.get_info_text() == ""
        assert adapter.get_dynamic_info_text() == ""
        assert adapter.get_entropy_pattern() == ""
        assert adapter.get_pe_version_info_text() == ""
        assert adapter.get_pe_security_text() == ""
        assert adapter.get_header_text() == ""
        assert adapter.get_headers_json() is None
        assert adapter.get_strings_text() == ""
        assert adapter.get_strings_filtered("iz~test") == ""
        assert adapter.get_entry_info() == []
        assert adapter.get_pe_header() == {}
        assert adapter.get_pe_optional_header() == {}
        assert adapter.get_data_directories() == []
        assert adapter.get_resources_info() == []
        assert adapter.get_function_info(0) == []
        assert adapter.get_disasm_text() == ""
        assert adapter.search_hex_json("90") == []
        assert adapter.search_text("test") == ""
        assert adapter.search_hex("90") == ""
    finally:
        os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)


def test_adapter_with_fake_r2_invalid_responses() -> None:
    class FakeR2:
        def __init__(self, mapping):
            self._mapping = mapping

        def cmd(self, command: str):
            return self._mapping.get(command, "")

        def cmdj(self, command: str):
            return self._mapping.get(command, None)

        def __repr__(self) -> str:
            return "FakeR2()"

    fake = FakeR2(
        {
            "i": 123,
            "ij": "not json",
            "iSj": "[]",
            "p8 4 @ 0": "ZZ",
            "/c test": "",
            "/x 90": "",
        }
    )
    adapter = R2PipeAdapter(fake)
    assert adapter.cmd("i") == "123"
    assert adapter.get_file_info() == {}
    assert adapter.get_sections() == []
    assert adapter.read_bytes(0, 4) == b""
    assert adapter.search_text("test") == ""
    assert adapter.search_hex("90") == ""


def test_adapter_cmdj_with_fake_r2() -> None:
    class FakeR2:
        def cmd(self, command: str):
            return "{}"

        def cmdj(self, command: str):
            return {"ok": True}

        def __repr__(self) -> str:
            return "FakeR2Cmdj()"

    adapter = R2PipeAdapter(FakeR2())
    assert adapter.cmdj("ij") == {"ok": True}


def test_adapter_cached_query_dict_cache_and_default() -> None:
    class FakeR2:
        def cmd(self, command: str):
            return "{}"

        def cmdj(self, command: str):
            return None

    adapter = R2PipeAdapter(FakeR2())
    adapter._cache["ij"] = {"cached": True}
    assert adapter._cached_query("ij", "dict") == {"cached": True}
    assert adapter._cached_query("nope", "dict", default={"x": 1}) == {"x": 1}


def test_adapter_get_file_info_cache_and_error() -> None:
    class FakeR2:
        def cmd(self, command: str):
            return '{"a": 1}'

        def cmdj(self, command: str):
            return None

    adapter = R2PipeAdapter(FakeR2())
    first = adapter.get_file_info()
    assert isinstance(first, dict)
    second = adapter.get_file_info()
    assert second == first

    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "get_file_info"
    try:
        assert adapter.get_file_info() == {}
    finally:
        os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)


def test_adapter_error_branches() -> None:
    class FakeR2:
        def cmd(self, command: str):
            return "ok"

        def cmdj(self, command: str):
            return None

    adapter = R2PipeAdapter(FakeR2())

    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "get_functions_at"
    try:
        assert adapter.get_functions_at(0) == []
    finally:
        os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)

    assert adapter.analyze_all() == "ok"

    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "_cached_query"
    try:
        assert adapter.get_strings_basic() == []
    finally:
        os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)


def test_adapter_pe_header_dict_and_read_bytes_errors() -> None:
    class FakeR2:
        def cmd(self, command: str):
            if command.startswith("p8"):
                return ""
            if command == "ihj":
                return '{"k": 1}'
            return "ok"

        def cmdj(self, command: str):
            return None

    adapter = R2PipeAdapter(FakeR2())
    assert adapter.get_pe_header() == {"k": 1}
    assert adapter.read_bytes(0, 4) == b""

    class FakeR2Bytes:
        def cmd(self, command: str):
            return b"00"

        def cmdj(self, command: str):
            return None

    adapter_bytes = R2PipeAdapter(FakeR2Bytes())
    assert adapter_bytes.read_bytes(0, 2) == b""

    class FakeR2Obj:
        def cmd(self, command: str):
            return object()

        def cmdj(self, command: str):
            return None

    adapter_obj = R2PipeAdapter(FakeR2Obj())
    assert adapter_obj.read_bytes(0, 2) == b""

    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "read_bytes"
    try:
        assert adapter.read_bytes(0, 2) == b""
    finally:
        os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)

    class FakeR2Text:
        def cmd(self, command: str):
            if command == "ihj":
                return '"text"'
            return "ok"

        def cmdj(self, command: str):
            return None

    adapter_text = R2PipeAdapter(FakeR2Text())
    assert adapter_text.get_pe_header() == {}


def test_adapter_force_error_specific_method() -> None:
    class FakeR2:
        def cmd(self, command: str):
            return "ok"

        def cmdj(self, command: str):
            return None

    adapter = R2PipeAdapter(FakeR2())
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "get_info_text"
    try:
        assert adapter.get_info_text() == ""
    finally:
        os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
