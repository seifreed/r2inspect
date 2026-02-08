from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.r2_suppress import (
    R2PipeErrorSuppressor,
    _parse_raw_result,
    silent_cmdj,
    suppress_r2pipe_errors,
)


class BadStr:
    def __str__(self) -> str:
        raise ValueError("bad str")


class ErroringFormatter(OutputFormatter):
    def _extract_csv_data(self, data: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("explode")


class DummyR2:
    def __init__(self, cmdj_result=None, cmd_result: str = "") -> None:
        self._cmdj_result = cmdj_result
        self._cmd_result = cmd_result

    def cmdj(self, command: str):
        return self._cmdj_result

    def cmd(self, command: str) -> str:
        return self._cmd_result


class DummyR2CmdjError(DummyR2):
    def cmdj(self, command: str):
        raise TypeError("bad cmdj")


@pytest.mark.unit
def test_output_formatter_json_and_csv_variants() -> None:
    results = {
        "file_info": {
            "name": "sample.bin",
            "size": 10,
            "file_type": "PE32+ executable",
            "md5": "a",
            "sha1": "b",
            "sha256": "c",
            "sha512": "d",
            "compile_time": "2025-01-01",
        },
        "pe_info": {"imphash": "deadbeef", "compile_time": "2025"},
        "ssdeep": {"hash_value": "ss"},
        "tlsh": {
            "binary_tlsh": "t1",
            "text_section_tlsh": "t2",
            "stats": {"functions_with_tlsh": 2},
        },
        "telfhash": {"telfhash": "tf", "filtered_symbols": 3},
        "rich_header": {
            "xor_key": 4660,
            "checksum": 22136,
            "richpe_hash": "rh",
            "compilers": [{"compiler_name": "MSVC", "count": 2}],
        },
        "imports": [{"name": "KERNEL32.dll"}],
        "exports": ["Exported"],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "yara_matches": [{"rule": "TestRule"}],
        "compiler": {"compiler": "MSVC", "version": "1", "confidence": 0.9},
        "function_analysis": {"total_functions": 5},
        "machoc_analysis": {"unique_hashes": 3, "duplicate_functions": 1},
    }
    formatter = OutputFormatter(results)
    json_text = formatter.to_json()
    assert json.loads(json_text)["file_info"]["name"] == "sample.bin"

    csv_text = formatter.to_csv()
    assert "sample.bin" in csv_text
    assert "deadbeef" in csv_text


@pytest.mark.unit
def test_output_formatter_json_error_path() -> None:
    formatter = OutputFormatter({"bad": BadStr()})
    payload = formatter.to_json()
    assert "JSON serialization failed" in payload


@pytest.mark.unit
def test_output_formatter_csv_error_path() -> None:
    formatter = ErroringFormatter({})
    csv_text = formatter.to_csv()
    assert "CSV Export Failed" in csv_text


@pytest.mark.unit
def test_r2_suppressor_and_silent_cmdj_paths() -> None:
    # Context manager restores stdout/stderr
    with R2PipeErrorSuppressor() as suppressor:
        assert suppressor.original_stdout is not None
        assert suppressor.original_stderr is not None

    # silent_cmdj returns default when no instance
    assert silent_cmdj(None, "ij", default={"ok": False}) == {"ok": False}

    # cmdj result is used
    instance = DummyR2(cmdj_result={"ok": True})
    assert silent_cmdj(instance, "ij", default=None) == {"ok": True}

    # cmdj raises -> fallback to cmd parsing
    instance = DummyR2CmdjError(cmdj_result=None, cmd_result='{"x": 1}')
    assert silent_cmdj(instance, "ij", default=None) == {"x": 1}


@pytest.mark.unit
def test_parse_raw_result_variants_and_context_manager() -> None:
    assert _parse_raw_result('{"a": 1}') == {"a": 1}
    assert _parse_raw_result("  value  ") == "value"
    assert _parse_raw_result("") is None

    with suppress_r2pipe_errors():
        pass
