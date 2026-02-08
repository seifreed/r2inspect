from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer

pytestmark = [pytest.mark.unit, pytest.mark.requires_r2]


def _open_session(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    return session, R2PipeAdapter(r2)


def test_r2_session_fat_macho_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fat_path = tmp_path / "fat.bin"
    header = struct.pack(">I", 0xCAFEBABE) + struct.pack(">I", 1)
    arch_entry = struct.pack(">IIIII", 0x01000007, 0, 0, 0, 0)
    fat_path.write_bytes(header + arch_entry)

    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "1")
    session = R2Session(str(fat_path))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches

    flags = session._select_r2_flags()
    assert "-2" in flags
    assert "-M" in flags
    assert "-NN" in flags

    non_fat = tmp_path / "plain.bin"
    non_fat.write_bytes(b"MZ" + b"\x00" * 6)
    plain_session = R2Session(str(non_fat))
    assert plain_session._detect_fat_macho_arches() == set()


def test_r2_session_timeouts_and_analysis_controls(
    samples_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, _adapter = _open_session(pe_path)
    try:
        monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "i")
        assert session._run_cmd_with_timeout("i", 0.01) is False

        monkeypatch.delenv("R2INSPECT_FORCE_CMD_TIMEOUT", raising=False)
        assert session._run_cmd_with_timeout("i", 1.0) is True

        monkeypatch.setenv("R2INSPECT_ANALYSIS_DEPTH", "0")
        assert session._perform_initial_analysis(0.1) is True

        monkeypatch.setenv("R2INSPECT_ANALYSIS_DEPTH", "1")
        assert session._perform_initial_analysis(1_000_000.0) is True
    finally:
        session.close()

    empty_session = R2Session(str(pe_path))
    with pytest.raises(RuntimeError):
        empty_session._run_basic_info_check()


def test_function_analyzer_real_and_helpers(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_session(pe_path)
    try:
        analyzer = FunctionAnalyzer(adapter, filename=str(pe_path))
        result = analyzer.analyze_functions()
        assert "total_functions" in result

        functions = analyzer._get_functions()
        if functions:
            complexity = analyzer._calculate_cyclomatic_complexity(functions[0])
            assert isinstance(complexity, int)

        assert analyzer._classify_function_type("kernel32!printf", {"size": 20}) == "library"
        assert analyzer._classify_function_type("j_thunk", {"size": 5}) == "thunk"
        assert analyzer._classify_function_type("main", {"size": 50}) == "user"
        assert analyzer._classify_function_type("other", {"size": 50}) == "unknown"

        assert analyzer._calculate_std_dev([]) == 0.0
        assert analyzer._calculate_std_dev([1.0]) == 0.0
        assert analyzer._calculate_std_dev([1.0, 3.0]) > 0.0

        coverage = analyzer._analyze_function_coverage(
            [{"size": 10, "nbbs": 1}, {"size": 0, "nbbs": 0}]
        )
        assert coverage["total_functions"] == 2
        assert coverage["functions_with_size"] == 1

        similarities = analyzer.get_function_similarity({"a": "h1", "b": "h1", "c": "h2"})
        assert "h1" in similarities

        summary = analyzer.generate_machoc_summary({"machoc_hashes": {"a": "h1", "b": "h1"}})
        assert summary["duplicate_function_groups"] == 1
        assert analyzer.generate_machoc_summary({"machoc_hashes": {}})["error"]
        assert analyzer._calculate_cyclomatic_complexity({"addr": None}) == 0
    finally:
        session.close()

    tiny_path = samples_dir / "edge_tiny.bin"
    tiny_session, tiny_adapter = _open_session(tiny_path)
    try:
        tiny_analyzer = FunctionAnalyzer(tiny_adapter, filename=str(tiny_path))
        tiny_result = tiny_analyzer.analyze_functions()
        assert tiny_result["total_functions"] == 0
    finally:
        tiny_session.close()


def test_resource_version_and_strings(tmp_path: Path) -> None:
    data = bytearray(256)
    data[0:4] = bytes([0xBD, 0x04, 0xEF, 0xFE])
    data[8:12] = struct.pack("<I", (1 << 16) | 2)
    data[12:16] = struct.pack("<I", (3 << 16) | 4)

    key = "CompanyName".encode("utf-16le")
    key_pos = 32
    data[key_pos : key_pos + len(key)] = key
    value_pos = key_pos + len(key) + 4
    value = "TestCo".encode("utf-16le") + b"\x00\x00"
    data[value_pos : value_pos + len(value)] = value

    text_pos = 128
    text = "Hello".encode("utf-16le") + b"\x00\x00"
    data[text_pos : text_pos + len(text)] = text

    file_path = tmp_path / "version.bin"
    file_path.write_bytes(bytes(data))

    session, adapter = _open_session(file_path)
    try:
        analyzer = ResourceAnalyzer(adapter)
        version_payload = analyzer._read_version_info_data(0, len(data))
        assert version_payload is not None
        assert analyzer._extract_version_strings(version_payload)

        class _InlineResourceAnalyzer(ResourceAnalyzer):
            def _read_version_info_data(self, _offset: int, _size: int):  # type: ignore[override]
                return list(data)

        inline_analyzer = _InlineResourceAnalyzer(adapter)
        version_info = inline_analyzer._parse_version_info(4, len(data))
        assert version_info is not None
        assert version_info["file_version"] == "1.2.3.4"
        assert "CompanyName" in version_info["strings"]

        text_out = analyzer._read_resource_as_string(text_pos, len(text))
        assert text_out and "Hello" in text_out
    finally:
        session.close()


def test_hashing_analyzers_real(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    elf_path = samples_dir / "hello_elf"

    ssdeep_analyzer = SSDeepAnalyzer(str(pe_path))
    ssdeep_result = ssdeep_analyzer.analyze()
    if ssdeep_result["available"]:
        assert ssdeep_result["hash_value"]
    else:
        assert ssdeep_result["error"]

    elf_session, elf_adapter = _open_session(elf_path)
    try:
        telfhash_analyzer = TelfhashAnalyzer(elf_adapter, filepath=str(elf_path))
        telf_result = telfhash_analyzer.analyze_symbols()
        if telf_result["available"]:
            assert telf_result["is_elf"] is True
        else:
            assert telf_result["error"]
    finally:
        elf_session.close()

    pe_session, pe_adapter = _open_session(pe_path)
    try:
        telfhash_pe = TelfhashAnalyzer(pe_adapter, filepath=str(pe_path))
        assert telfhash_pe._is_elf_file() is False

        if TLSH_AVAILABLE:
            tlsh_analyzer = TLSHAnalyzer(pe_adapter, filename=str(pe_path))
            tlsh_result = tlsh_analyzer.analyze_sections()
            assert tlsh_result["available"] is True
    finally:
        pe_session.close()


def test_rich_header_helpers(tmp_path: Path) -> None:
    rich_analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(tmp_path / "dummy.bin"))
    data = b"xxRich\x01\x02\x03\x04yyRich\x05\x06\x07\x08DanS"
    assert rich_analyzer._find_all_occurrences(data, b"Rich") == [2, 12]
    assert rich_analyzer._offset_pair_valid(4, 12, 16) is True
    assert rich_analyzer._find_rich_positions(data) == [2, 12]

    key_data = bytearray(b"Rich\x01\x02\x03\x04")
    assert rich_analyzer._is_valid_rich_key(key_data, 0) is True
    assert rich_analyzer._find_dans_before_rich(b"DanSRich", 4) == 0

    dos_stub = b"\x00" * 8 + b"RICH"
    assert rich_analyzer._estimate_dans_start(dos_stub, 8) is not None

    assert rich_analyzer._extract_encoded_from_stub(b"DanSRich", 0, 4) is None
    checksum = rich_analyzer._calculate_rich_checksum(b"MZ" + b"\x00" * 64, 64, [])
    assert isinstance(checksum, int)


def test_richpe_hash_from_file(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    value = RichHeaderAnalyzer.calculate_richpe_hash_from_file(str(pe_path))
    if value is not None:
        assert isinstance(value, str)
