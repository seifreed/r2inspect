from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer

pytestmark = pytest.mark.requires_r2


@pytest.fixture()
def adapters(samples_dir: Path):
    paths = {
        "pe": samples_dir / "hello_pe.exe",
        "elf": samples_dir / "hello_elf",
        "macho": samples_dir / "hello_macho",
    }
    sessions: dict[str, R2Session] = {}
    adapters: dict[str, R2PipeAdapter] = {}
    for key, path in paths.items():
        session = R2Session(str(path))
        file_size_mb = path.stat().st_size / (1024 * 1024)
        r2 = session.open(file_size_mb)
        sessions[key] = session
        adapters[key] = R2PipeAdapter(r2)
    try:
        yield adapters, paths
    finally:
        for session in sessions.values():
            session.close()


def test_function_analyzer_real(adapters) -> None:
    adapter_map, paths = adapters
    analyzer = FunctionAnalyzer(adapter_map["pe"], filename=str(paths["pe"]))
    results = analyzer.analyze_functions()
    assert isinstance(results, dict)

    functions = analyzer._get_functions()
    assert isinstance(functions, list)

    if functions:
        first = functions[0]
        func_addr = first.get("addr") or first.get("offset")
        func_size = first.get("size", 0) or 1
        if func_addr is not None:
            mnemonics = analyzer._extract_function_mnemonics(
                first.get("name", "f"), int(func_size), int(func_addr)
            )
            assert isinstance(mnemonics, list)

    assert isinstance(analyzer._should_run_full_analysis(), bool)


def test_simhash_analyzer_real(adapters) -> None:
    adapter_map, paths = adapters
    analyzer = SimHashAnalyzer(adapter_map["pe"], filepath=str(paths["pe"]))
    result = analyzer.analyze()
    assert isinstance(result, dict)

    detailed = analyzer.analyze_detailed()
    assert isinstance(detailed, dict)


def test_ssdeep_analyzer_real_and_errors(samples_dir: Path, tmp_path: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    analyzer = SSDeepAnalyzer(str(pe_path))
    ok = analyzer.analyze()
    assert isinstance(ok, dict)

    missing_path = tmp_path / "missing.bin"
    analyzer_missing = SSDeepAnalyzer(str(missing_path))
    missing_result = analyzer_missing.analyze()
    assert missing_result["available"] is False
    assert missing_result["error"]

    small_path = tmp_path / "tiny.bin"
    small_path.write_bytes(b"")
    analyzer_small = SSDeepAnalyzer(str(small_path), min_file_size=1)
    small_result = analyzer_small.analyze()
    assert small_result["available"] is False
    assert "too small" in (small_result["error"] or "").lower()


def test_telfhash_analyzer_real(adapters, samples_dir: Path) -> None:
    adapter_map, paths = adapters
    analyzer = TelfhashAnalyzer(adapter_map["elf"], filepath=str(paths["elf"]))
    result = analyzer.analyze()
    assert isinstance(result, dict)

    detailed = analyzer.analyze_symbols()
    assert isinstance(detailed, dict)

    non_elf = samples_dir / "hello_pe.exe"
    analyzer_non = TelfhashAnalyzer(adapter_map["pe"], filepath=str(non_elf))
    non_result = analyzer_non.analyze()
    assert non_result["available"] is False or non_result["hash_value"] is None


def test_tlsh_analyzer_real(adapters, tmp_path: Path) -> None:
    adapter_map, paths = adapters
    pe_path = paths["pe"]
    adapter = adapter_map["pe"]
    analyzer = TLSHAnalyzer(adapter, str(pe_path))
    result = analyzer.analyze()
    assert isinstance(result, dict)

    missing_path = tmp_path / "missing.bin"
    analyzer_missing = TLSHAnalyzer(adapter, str(missing_path))
    missing_result = analyzer_missing.analyze()
    assert missing_result["available"] is False
