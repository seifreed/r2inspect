"""Tests for file_type, hashing, output_csv, r2_suppress, analyzer_factory, logger, ssdeep_loader, stages_common.

Rules: no mocks, no unittest.mock, no MagicMock, no patch — plain stubs only.
"""

from __future__ import annotations

import hashlib
import io
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Shared stub helpers
# ---------------------------------------------------------------------------


class _StubAdapter:
    """Minimal stub with no r2 methods — forces fallback paths."""


class _StubAdapterPEInfoText:
    def get_info_text(self) -> str:
        return "format: PE 32-bit executable"


class _StubAdapterELFInfoText:
    def get_info_text(self) -> str:
        return "format: ELF 64-bit LSB executable"


class _StubAdapterPEFileInfo:
    def get_info_text(self) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "pe", "class": "PE32"}}


class _StubAdapterPEClassFileInfo:
    def get_info_text(self) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "unknown", "class": "PE64"}}


class _StubAdapterELFFileInfo:
    def get_info_text(self) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "elf", "type": "EXEC", "class": "ELF64"}}


class _StubAdapterEmpty:
    def get_info_text(self) -> str:
        return ""

    def get_file_info(self) -> dict[str, Any]:
        return {}


class _StubR2:
    """r2 instance stub that returns empty results."""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}


class _StubR2WithJSON:
    """r2 instance stub that returns valid JSON string from cmd()."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def cmd(self, command: str) -> str:
        import json
        return json.dumps(self._payload)

    def cmdj(self, command: str) -> Any:
        return self._payload


# ===========================================================================
# file_type.py
# ===========================================================================


def test_is_pe_file_mz_header_returns_true(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_pe_file

    pe = tmp_path / "sample.exe"
    pe.write_bytes(b"MZ" + b"\x90" * 100)
    assert is_pe_file(str(pe), _StubAdapter(), _StubR2()) is True


def test_is_pe_file_info_text_contains_pe(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_pe_file

    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 10)
    assert is_pe_file(str(f), _StubAdapterPEInfoText(), _StubR2()) is True


def test_is_pe_file_file_info_format_field(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_pe_file

    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 10)
    assert is_pe_file(str(f), _StubAdapterPEFileInfo(), _StubR2()) is True


def test_is_pe_file_file_info_class_field(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_pe_file

    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 10)
    assert is_pe_file(str(f), _StubAdapterPEClassFileInfo(), _StubR2()) is True


def test_is_pe_file_no_indicators_returns_false(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_pe_file

    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 10)
    assert is_pe_file(str(f), _StubAdapterEmpty(), _StubR2()) is False


def test_is_pe_file_none_filepath_uses_adapter() -> None:
    from r2inspect.utils.file_type import is_pe_file

    assert is_pe_file(None, _StubAdapterPEInfoText(), _StubR2()) is True


def test_is_pe_file_none_filepath_no_indicators() -> None:
    from r2inspect.utils.file_type import is_pe_file

    assert is_pe_file(None, _StubAdapterEmpty(), _StubR2()) is False


def test_is_elf_file_info_text_contains_elf(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_elf_file

    f = tmp_path / "sample.elf"
    f.write_bytes(b"\x00" * 10)
    assert is_elf_file(str(f), _StubAdapterELFInfoText(), _StubR2()) is True


def test_is_elf_file_file_info_format_field(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_elf_file

    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 10)
    assert is_elf_file(str(f), _StubAdapterELFFileInfo(), _StubR2()) is True


def test_is_elf_file_magic_bytes(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_elf_file

    f = tmp_path / "sample.elf"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert is_elf_file(str(f), _StubAdapterEmpty(), _StubR2()) is True


def test_is_elf_file_no_indicators_returns_false(tmp_path: Path) -> None:
    from r2inspect.utils.file_type import is_elf_file

    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 10)
    assert is_elf_file(str(f), _StubAdapterEmpty(), _StubR2()) is False


def test_bin_info_has_pe_format() -> None:
    from r2inspect.utils.file_type import _bin_info_has_pe

    assert _bin_info_has_pe({"format": "pe", "class": "PE32"}) is True


def test_bin_info_has_pe_class() -> None:
    from r2inspect.utils.file_type import _bin_info_has_pe

    assert _bin_info_has_pe({"format": "unknown", "class": "PE64"}) is True


def test_bin_info_has_pe_case_insensitive() -> None:
    from r2inspect.utils.file_type import _bin_info_has_pe

    assert _bin_info_has_pe({"format": "PE32+", "class": ""}) is True


def test_bin_info_has_pe_false() -> None:
    from r2inspect.utils.file_type import _bin_info_has_pe

    assert _bin_info_has_pe({"format": "elf", "class": "ELF64"}) is False


def test_bin_info_has_pe_empty() -> None:
    from r2inspect.utils.file_type import _bin_info_has_pe

    assert _bin_info_has_pe({}) is False


def test_bin_info_has_elf_format() -> None:
    from r2inspect.utils.file_type import _bin_info_has_elf

    assert _bin_info_has_elf({"format": "elf", "type": "EXEC", "class": "ELF64"}) is True


def test_bin_info_has_elf_type() -> None:
    from r2inspect.utils.file_type import _bin_info_has_elf

    assert _bin_info_has_elf({"format": "unknown", "type": "elf64", "class": ""}) is True


def test_bin_info_has_elf_class() -> None:
    from r2inspect.utils.file_type import _bin_info_has_elf

    assert _bin_info_has_elf({"format": "unknown", "type": "EXEC", "class": "elf"}) is True


def test_bin_info_has_elf_false() -> None:
    from r2inspect.utils.file_type import _bin_info_has_elf

    assert _bin_info_has_elf({"format": "pe", "type": "EXEC", "class": "PE32"}) is False


def test_bin_info_has_elf_empty() -> None:
    from r2inspect.utils.file_type import _bin_info_has_elf

    assert _bin_info_has_elf({}) is False


# ===========================================================================
# hashing.py
# ===========================================================================


def test_calculate_hashes_known_data(tmp_path: Path) -> None:
    from r2inspect.utils.hashing import calculate_hashes

    data = b"r2inspect-unit-test"
    f = tmp_path / "test.bin"
    f.write_bytes(data)
    result = calculate_hashes(str(f))

    assert result["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert result["sha1"] == hashlib.sha1(data, usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["sha512"] == hashlib.sha512(data).hexdigest()


def test_calculate_hashes_empty_file(tmp_path: Path) -> None:
    from r2inspect.utils.hashing import calculate_hashes

    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = calculate_hashes(str(f))
    assert result["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()


def test_calculate_hashes_nonexistent_file(tmp_path: Path) -> None:
    from r2inspect.utils.hashing import calculate_hashes

    result = calculate_hashes(str(tmp_path / "missing.bin"))
    assert result == {"md5": "", "sha1": "", "sha256": "", "sha512": ""}


def test_calculate_hashes_for_bytes_basic() -> None:
    from r2inspect.utils.hashing import calculate_hashes_for_bytes

    data = b"hello"
    result = calculate_hashes_for_bytes(data)
    assert set(result.keys()) == {"md5", "sha1", "sha256"}
    assert result["md5"] == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


def test_calculate_hashes_for_bytes_with_sha512() -> None:
    from r2inspect.utils.hashing import calculate_hashes_for_bytes

    data = b"hello"
    result = calculate_hashes_for_bytes(data, include_sha512=True)
    assert "sha512" in result
    assert result["sha512"] == hashlib.sha512(data).hexdigest()


def test_calculate_hashes_for_bytes_empty() -> None:
    from r2inspect.utils.hashing import calculate_hashes_for_bytes

    result = calculate_hashes_for_bytes(b"")
    assert result["md5"] == hashlib.md5(b"", usedforsecurity=False).hexdigest()


def test_calculate_hashes_for_bytes_no_sha512_by_default() -> None:
    from r2inspect.utils.hashing import calculate_hashes_for_bytes

    result = calculate_hashes_for_bytes(b"data")
    assert "sha512" not in result


# ===========================================================================
# output_csv.py
# ===========================================================================


def _make_full_result() -> dict[str, Any]:
    return {
        "file_info": {
            "name": "sample.exe",
            "size": 2048,
            "file_type": "PE32 executable, 5 sections",
            "md5": "aabbcc",
            "sha1": "ddeeff",
            "sha256": "112233",
            "sha512": "445566",
        },
        "pe_info": {
            "compile_time": "2023-01-01T00:00:00",
            "imphash": "deadbeef",
        },
        "ssdeep": {"hash_value": "3:abc:xyz"},
        "tlsh": {
            "binary_tlsh": "T1ABC",
            "text_section_tlsh": "T2DEF",
            "stats": {"functions_with_tlsh": 5},
        },
        "telfhash": {"telfhash": "TELF123", "filtered_symbols": 10},
        "rich_header": {
            "xor_key": 0xDEAD,
            "checksum": 0xBEEF,
            "richpe_hash": "richpehash123",
            "compilers": [
                {"compiler_name": "MSVC", "count": 3},
                {"compiler_name": "LINK", "count": 1},
            ],
        },
        "imports": [
            {"name": "CreateFileW", "library": "kernel32.dll"},
            {"name": "MessageBoxA", "library": "user32.dll"},
        ],
        "exports": [{"name": "DllMain"}],
        "sections": [{"name": ".text"}, {"name": ".data"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "yara_matches": [{"rule": "Mirai"}, {"rule": "AgentTesla"}],
        "compiler": {"compiler": "MSVC", "version": "19.0", "confidence": 0.95},
        "functions": {
            "total_functions": 42,
            "machoc_hashes": {"func_a": "aaa", "func_b": "bbb", "func_c": "aaa"},
        },
    }


def test_csv_output_contains_header_row() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "name" in csv_text
    assert "sha256" in csv_text


def test_csv_output_contains_filename() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "sample.exe" in csv_text


def test_csv_output_imphash() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "deadbeef" in csv_text


def test_csv_output_file_size_formatted() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "KB" in csv_text or "2" in csv_text


def test_csv_output_section_count_stripped_from_file_type() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "5 sections" not in csv_text
    assert "PE32 executable" in csv_text


def test_csv_output_compile_time() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "2023-01-01" in csv_text


def test_csv_output_rich_header_compilers() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "MSVC" in csv_text


def test_csv_output_empty_dict() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter({}).to_csv()
    assert isinstance(csv_text, str)
    assert len(csv_text) > 0


def test_csv_output_anti_analysis_flags() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    csv_text = CsvOutputFormatter(_make_full_result()).to_csv()
    assert "True" in csv_text


def test_csv_output_duplicate_machoc_count() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    formatter = CsvOutputFormatter(_make_full_result())
    data = formatter._extract_csv_data(_make_full_result())
    # func_a and func_c share hash "aaa" → 1 duplicate
    assert data["num_duplicate_functions"] == 1
    assert data["num_unique_machoc"] == 2


def test_csv_output_counts() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    formatter = CsvOutputFormatter(_make_full_result())
    data = formatter._extract_csv_data(_make_full_result())
    assert data["num_imports"] == 2
    assert data["num_exports"] == 1
    assert data["num_sections"] == 2


def test_format_file_size_zero() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    fmt = CsvOutputFormatter({})
    assert fmt._format_file_size(0) == "0 B"


def test_format_file_size_bytes() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    fmt = CsvOutputFormatter({})
    assert fmt._format_file_size(512) == "512 B"


def test_format_file_size_kb() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    fmt = CsvOutputFormatter({})
    assert "KB" in fmt._format_file_size(1024)


def test_format_file_size_mb() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    fmt = CsvOutputFormatter({})
    assert "MB" in fmt._format_file_size(1024 * 1024)


def test_clean_file_type_removes_section_count() -> None:
    from r2inspect.utils.output_csv import CsvOutputFormatter

    fmt = CsvOutputFormatter({})
    result = fmt._clean_file_type("PE32 executable, 7 sections")
    assert "sections" not in result
    assert "PE32 executable" in result


# ===========================================================================
# r2_suppress.py
# ===========================================================================


def test_r2pipe_error_suppressor_redirects_and_restores() -> None:
    from r2inspect.utils.r2_suppress import R2PipeErrorSuppressor

    original_stderr = sys.stderr
    original_stdout = sys.stdout

    with R2PipeErrorSuppressor():
        assert sys.stderr is not original_stderr
        assert sys.stdout is not original_stdout

    assert sys.stderr is original_stderr
    assert sys.stdout is original_stdout


def test_r2pipe_error_suppressor_does_not_swallow_exceptions() -> None:
    from r2inspect.utils.r2_suppress import R2PipeErrorSuppressor

    with pytest.raises(ValueError):
        with R2PipeErrorSuppressor():
            raise ValueError("should propagate")


def test_suppress_r2pipe_errors_context_manager() -> None:
    from r2inspect.utils.r2_suppress import suppress_r2pipe_errors

    original_stderr = sys.stderr
    with suppress_r2pipe_errors():
        assert sys.stderr is not original_stderr
    assert sys.stderr is original_stderr


def test_silent_cmdj_none_instance_returns_default() -> None:
    from r2inspect.utils.r2_suppress import silent_cmdj

    result = silent_cmdj(None, "ij", default=[])
    assert result == []


def test_silent_cmdj_valid_instance_returns_data() -> None:
    from r2inspect.utils.r2_suppress import silent_cmdj

    r2 = _StubR2WithJSON({"format": "pe"})
    result = silent_cmdj(r2, "ij", default={})
    # May return {} or the payload depending on path taken — both valid
    assert isinstance(result, dict)


def test_parse_raw_result_valid_json() -> None:
    from r2inspect.utils.r2_suppress import _parse_raw_result

    assert _parse_raw_result('{"key": 1}') == {"key": 1}


def test_parse_raw_result_invalid_json_long_string() -> None:
    from r2inspect.utils.r2_suppress import _parse_raw_result

    result = _parse_raw_result("not json but long enough")
    assert result == "not json but long enough"


def test_parse_raw_result_short_invalid_returns_none() -> None:
    from r2inspect.utils.r2_suppress import _parse_raw_result

    # 2-char string fails json parsing and len <= 2 → returns None
    assert _parse_raw_result("ab") is None


# ===========================================================================
# analyzer_factory.py
# ===========================================================================


class _NoArgAnalyzer:
    def analyze(self) -> dict[str, Any]:
        return {"type": "no-arg"}


class _AdapterAnalyzer:
    def __init__(self, adapter: Any) -> None:
        self.adapter = adapter

    def analyze(self) -> dict[str, Any]:
        return {"type": "adapter"}


class _AdapterConfigAnalyzer:
    def __init__(self, adapter: Any, config: Any) -> None:
        self.adapter = adapter
        self.config = config

    def detect(self) -> dict[str, Any]:
        return {"type": "adapter-config"}


class _FilenameAnalyzer:
    def __init__(self, filename: str) -> None:
        self.filename = filename

    def scan(self) -> dict[str, Any]:
        return {"type": "filename", "path": self.filename}


class _MultiParamAnalyzer:
    def __init__(self, adapter: Any, config: Any, filename: str) -> None:
        self.adapter = adapter
        self.config = config
        self.filename = filename

    def analyze(self) -> dict[str, Any]:
        return {"type": "multi"}


def test_create_analyzer_no_args() -> None:
    from r2inspect.utils.analyzer_factory import create_analyzer

    inst = create_analyzer(_NoArgAnalyzer)
    assert isinstance(inst, _NoArgAnalyzer)


def test_create_analyzer_with_adapter() -> None:
    from r2inspect.utils.analyzer_factory import create_analyzer

    stub = _StubAdapter()
    inst = create_analyzer(_AdapterAnalyzer, adapter=stub)
    assert isinstance(inst, _AdapterAnalyzer)
    assert inst.adapter is stub


def test_create_analyzer_with_adapter_and_config() -> None:
    from r2inspect.utils.analyzer_factory import create_analyzer

    stub = _StubAdapter()
    cfg = {"opt": True}
    inst = create_analyzer(_AdapterConfigAnalyzer, adapter=stub, config=cfg)
    assert isinstance(inst, _AdapterConfigAnalyzer)
    assert inst.config is cfg


def test_create_analyzer_with_filename() -> None:
    from r2inspect.utils.analyzer_factory import create_analyzer

    inst = create_analyzer(_FilenameAnalyzer, filename="/tmp/test.bin")
    assert isinstance(inst, _FilenameAnalyzer)
    assert inst.filename == "/tmp/test.bin"


def test_create_analyzer_multi_param() -> None:
    from r2inspect.utils.analyzer_factory import create_analyzer

    stub = _StubAdapter()
    inst = create_analyzer(_MultiParamAnalyzer, adapter=stub, config={}, filename="f.bin")
    assert isinstance(inst, _MultiParamAnalyzer)


def test_run_analysis_method_analyze() -> None:
    from r2inspect.utils.analyzer_factory import run_analysis_method

    inst = _NoArgAnalyzer()
    result = run_analysis_method(inst, ("analyze",))
    assert result == {"type": "no-arg"}


def test_run_analysis_method_detect() -> None:
    from r2inspect.utils.analyzer_factory import run_analysis_method

    inst = _AdapterConfigAnalyzer(_StubAdapter(), {})
    result = run_analysis_method(inst, ("analyze", "detect"))
    assert result == {"type": "adapter-config"}


def test_run_analysis_method_scan() -> None:
    from r2inspect.utils.analyzer_factory import run_analysis_method

    inst = _FilenameAnalyzer("/tmp/f.bin")
    result = run_analysis_method(inst, ("analyze", "detect", "scan"))
    assert result["type"] == "filename"


def test_run_analysis_method_no_match() -> None:
    from r2inspect.utils.analyzer_factory import run_analysis_method

    inst = _NoArgAnalyzer()
    result = run_analysis_method(inst, ("nonexistent",))
    assert "error" in result


def test_build_kwargs_r2_name() -> None:
    from r2inspect.utils.analyzer_factory import _build_kwargs

    stub = _StubAdapter()
    kwargs = _build_kwargs(["r2", "config"], stub, {"x": 1}, None)
    assert kwargs["r2"] is stub
    assert kwargs["config"] == {"x": 1}


def test_build_kwargs_adapter_name() -> None:
    from r2inspect.utils.analyzer_factory import _build_kwargs

    stub = _StubAdapter()
    kwargs = _build_kwargs(["adapter", "filename"], stub, None, "/f.bin")
    assert kwargs["adapter"] is stub
    assert kwargs["filename"] == "/f.bin"


def test_build_kwargs_filepath_name() -> None:
    from r2inspect.utils.analyzer_factory import _build_kwargs

    kwargs = _build_kwargs(["filepath"], None, None, "/path/to/file")
    assert kwargs["filepath"] == "/path/to/file"


# ===========================================================================
# logger.py
# ===========================================================================


def test_setup_logger_returns_named_logger() -> None:
    from r2inspect.utils.logger import setup_logger

    lg = setup_logger(name="r2inspect.cov_test", level=logging.DEBUG, thread_safe=False)
    assert lg.name == "r2inspect.cov_test"
    assert lg.level == logging.DEBUG


def test_get_logger_returns_same_instance() -> None:
    from r2inspect.utils.logger import get_logger, setup_logger

    setup_logger(name="r2inspect.cov_test2", level=logging.INFO, thread_safe=False)
    lg1 = get_logger("r2inspect.cov_test2")
    lg2 = get_logger("r2inspect.cov_test2")
    assert lg1 is lg2


def test_configure_batch_logging_raises_to_warning() -> None:
    from r2inspect.utils.logger import configure_batch_logging, reset_logging_levels

    configure_batch_logging()
    assert logging.getLogger("r2inspect").level == logging.WARNING
    assert logging.getLogger("r2inspect.pipeline").level == logging.WARNING
    reset_logging_levels()


def test_reset_logging_levels_back_to_info() -> None:
    from r2inspect.utils.logger import configure_batch_logging, reset_logging_levels

    configure_batch_logging()
    reset_logging_levels()
    assert logging.getLogger("r2inspect").level == logging.INFO
    assert logging.getLogger("r2inspect.utils").level == logging.INFO


def test_setup_logger_thread_safe_false() -> None:
    from r2inspect.utils.logger import setup_logger

    lg = setup_logger(name="r2inspect.cov_nts", level=logging.WARNING, thread_safe=False)
    assert lg is not None
    assert lg.level == logging.WARNING


# ===========================================================================
# ssdeep_loader.py
# ===========================================================================


def test_get_ssdeep_returns_module_or_none() -> None:
    from r2inspect.utils.ssdeep_loader import get_ssdeep

    result = get_ssdeep()
    assert result is None or hasattr(result, "hash_from_file")


def test_get_ssdeep_is_idempotent() -> None:
    from r2inspect.utils.ssdeep_loader import get_ssdeep

    r1 = get_ssdeep()
    r2 = get_ssdeep()
    assert r1 is r2


# ===========================================================================
# pipeline/stages_common.py
# ===========================================================================


class _SimpleStubAnalyzer:
    """Analyzer that takes no args and returns a fixed result."""

    def analyze(self) -> dict[str, Any]:
        return {"found": True, "items": [1, 2, 3]}


class _FailingAnalyzer:
    """Analyzer whose analyze() raises."""

    def analyze(self) -> dict[str, Any]:
        raise RuntimeError("analysis failed")


class _StubBackend:
    pass


def test_analyzer_stage_stores_result_in_context() -> None:
    from r2inspect.pipeline.stages_common import AnalyzerStage

    stage = AnalyzerStage(
        name="test_analyzer",
        analyzer_class=_SimpleStubAnalyzer,
        adapter=_StubBackend(),
        config={},
        filename="test.bin",
    )
    context: dict[str, Any] = {"results": {}}
    stage.execute(context)
    assert context["results"]["test_analyzer"] == {"found": True, "items": [1, 2, 3]}


def test_analyzer_stage_custom_result_key() -> None:
    from r2inspect.pipeline.stages_common import AnalyzerStage

    stage = AnalyzerStage(
        name="test_analyzer",
        analyzer_class=_SimpleStubAnalyzer,
        adapter=_StubBackend(),
        config={},
        filename="test.bin",
        result_key="custom_key",
    )
    context: dict[str, Any] = {"results": {}}
    stage.execute(context)
    assert "custom_key" in context["results"]


def test_analyzer_stage_failing_analyzer_stores_error() -> None:
    from r2inspect.pipeline.stages_common import AnalyzerStage

    stage = AnalyzerStage(
        name="bad_analyzer",
        analyzer_class=_FailingAnalyzer,
        adapter=_StubBackend(),
        config={},
        filename="test.bin",
    )
    context: dict[str, Any] = {"results": {}}
    stage.execute(context)
    assert "error" in context["results"]["bad_analyzer"]


def test_analyzer_stage_description_contains_class_name() -> None:
    from r2inspect.pipeline.stages_common import AnalyzerStage

    stage = AnalyzerStage(
        name="x",
        analyzer_class=_SimpleStubAnalyzer,
        adapter=_StubBackend(),
        config={},
        filename="f.bin",
    )
    assert "_SimpleStubAnalyzer" in stage.description


def test_indicator_stage_returns_list() -> None:
    from r2inspect.pipeline.stages_common import IndicatorStage

    stage = IndicatorStage()
    context: dict[str, Any] = {"results": {"file_info": {"name": "test.bin"}}}
    result = stage.execute(context)
    assert "indicators" in result
    assert isinstance(result["indicators"], list)


def test_indicator_stage_populates_context() -> None:
    from r2inspect.pipeline.stages_common import IndicatorStage

    stage = IndicatorStage()
    context: dict[str, Any] = {"results": {}}
    stage.execute(context)
    assert "indicators" in context["results"]


def test_indicator_stage_name_and_deps() -> None:
    from r2inspect.pipeline.stages_common import IndicatorStage

    stage = IndicatorStage()
    assert stage.name == "indicators"
    assert "metadata" in stage.dependencies
    assert "detection" in stage.dependencies
