from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

from r2inspect.utils import command_helpers
from r2inspect.utils import hashing as hashing_utils
from r2inspect.utils import r2_suppress, ssdeep_loader


class _Adapter:
    def __init__(self) -> None:
        self.last_address: int | None = None

    def search_hex_json(self, pattern: str) -> list[dict[str, Any]]:
        return [{"pattern": pattern}]

    def search_text(self, text: str) -> str:
        return f"text:{text}"

    def search_hex(self, pattern: str) -> str:
        return f"hex:{pattern}"

    def analyze_all(self) -> str:
        return "ok"

    def get_info_text(self) -> str:
        return "info"

    def get_strings_filtered(self, command: str) -> str:
        return f"strings:{command}"

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"addr": 1}]

    def get_functions_at(self, address: int) -> list[dict[str, Any]]:
        self.last_address = address
        return [{"addr": address}]

    def get_function_info(self, address: int) -> dict[str, Any]:
        return {"addr": address}

    def get_disasm(self, address: int | None = None, size: int | None = None) -> list[str]:
        return [f"{address}:{size}"]

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        return f"text:{address}:{size}"

    def get_cfg(self, address: int | None = None) -> dict[str, Any]:
        return {"addr": address}

    def read_bytes_list(self, address: int, size: int | None) -> list[int]:
        return [address, size or 0]

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes([address % 256] * size)


class _R2Dummy:
    def __init__(self, cmdj_result: Any = None, cmd_result: str = "") -> None:
        self._cmdj_result = cmdj_result
        self._cmd_result = cmd_result

    def cmdj(self, _command: str) -> Any:
        return self._cmdj_result

    def cmd(self, _command: str) -> str:
        return self._cmd_result


def test_command_helpers_parsing_and_dispatch() -> None:
    adapter = _Adapter()
    assert command_helpers.cmdj(adapter, None, "/xj dead", []) == [{"pattern": "dead"}]
    assert command_helpers.cmdj(adapter, None, "/c hello", []) == "text:hello"
    assert command_helpers.cmdj(adapter, None, "/x beef", []) == "hex:beef"
    assert command_helpers.cmd(adapter, None, "aaa") == "ok"
    assert command_helpers.cmd(adapter, None, "i") == "info"
    assert command_helpers.cmd(adapter, None, "iz~foo") == "strings:iz~foo"
    assert command_helpers.cmdj(adapter, None, "aflj @ 0x10", []) == [{"addr": 16}]
    assert adapter.last_address == 16
    assert command_helpers.cmdj(adapter, None, "afij @ 0x20", {}) == {"addr": 32}
    assert command_helpers.cmdj(adapter, None, "pdfj @ 0x30", []) == ["48:None"]
    assert command_helpers.cmdj(adapter, None, "pdj 4 @ 0x40", []) == ["64:4"]
    assert command_helpers.cmd(adapter, None, "pi 8 @ 0x50") == "text:80:8"
    assert command_helpers.cmdj(adapter, None, "agj @ 0x60", {}) == {"addr": 96}
    assert command_helpers.cmdj(adapter, None, "p8j 4 @ 0x70", []) == [112, 4]
    assert command_helpers.cmd(adapter, None, "p8 2 @ 0x80") == "8080"
    assert command_helpers.cmdj(adapter, None, "pxj 3 @ 0x90", []) == [144, 3]


def test_hashing_utils(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    data = b"hello world"
    sample.write_bytes(data)

    hashes = hashing_utils.calculate_hashes(str(sample))
    assert hashes["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(data).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(data).hexdigest()

    missing = hashing_utils.calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing["md5"] == ""

    directory_hashes = hashing_utils.calculate_hashes(str(tmp_path))
    assert directory_hashes["md5"].startswith("Error:")

    imports = [
        {"library": "KERNEL32.dll", "name": "CreateFileA"},
        {"library": "USER32.dll", "name": "MessageBoxA"},
    ]
    imphash = hashing_utils.calculate_imphash(imports)
    assert (
        imphash
        == hashlib.md5(
            b"kernel32.dll.createfilea,user32.dll.messageboxa", usedforsecurity=False
        ).hexdigest()
    )
    assert hashing_utils.calculate_imphash([]) is None
    assert hashing_utils.calculate_imphash([{"library": "", "name": ""}]) is None

    ssdeep = hashing_utils.calculate_ssdeep(str(sample))
    if ssdeep_loader.get_ssdeep() is None:
        assert ssdeep is None
    else:
        assert ssdeep


def test_ssdeep_loader_success_and_failure() -> None:
    ssdeep_loader._ssdeep_module = None
    module = ssdeep_loader.get_ssdeep()
    if module is not None:
        assert ssdeep_loader.get_ssdeep() is module

    original_sys_path = list(sys.path)
    original_module = sys.modules.pop("ssdeep", None)
    try:
        sys.path = []
        ssdeep_loader._ssdeep_module = None
        assert ssdeep_loader.get_ssdeep() is None
    finally:
        sys.path = original_sys_path
        if original_module is not None:
            sys.modules["ssdeep"] = original_module
        ssdeep_loader._ssdeep_module = None


def test_r2_suppress_helpers() -> None:
    assert r2_suppress.silent_cmdj(None, "ij", default={}) == {}

    r2_instance = _R2Dummy(cmdj_result={"ok": True})
    assert r2_suppress.silent_cmdj(r2_instance, "ij", default={}) == {"ok": True}

    class _TypeErrorCmdj(_R2Dummy):
        def cmdj(self, _command: str) -> Any:
            raise TypeError("boom")

    raw_json = _TypeErrorCmdj(cmdj_result=None, cmd_result='{"a": 1}')
    assert r2_suppress.silent_cmdj(raw_json, "ij", default={}) == {"a": 1}

    raw_text = _TypeErrorCmdj(cmdj_result=None, cmd_result="not-json")
    assert r2_suppress.silent_cmdj(raw_text, "ij", default={}) == "not-json"

    class _RaiseOSError(_R2Dummy):
        def cmdj(self, _command: str) -> Any:
            raise OSError("boom")

    assert r2_suppress.silent_cmdj(_RaiseOSError(), "ij", default=None) is None

    with r2_suppress.suppress_r2pipe_errors():
        assert True
