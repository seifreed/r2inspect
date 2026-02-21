from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.factory import create_inspector
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer
from r2inspect.utils.ssdeep_loader import get_ssdeep

pytestmark = pytest.mark.requires_r2


def test_resource_and_rich_header_real_edge_inputs(samples_dir: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    bad_pe = samples_dir / "edge_bad_pe.bin"
    tiny = samples_dir / "edge_tiny.bin"
    elf_sample = samples_dir / "hello_elf"

    for sample in (pe_sample, bad_pe, tiny):
        with create_inspector(str(sample)) as inspector:
            resource_result = ResourceAnalyzer(inspector.adapter).analyze()
            assert "available" in resource_result
            assert "resources" in resource_result
            if resource_result.get("available"):
                assert "resource_types" in resource_result
                assert "statistics" in resource_result

    with create_inspector(str(pe_sample)) as inspector:
        rich = RichHeaderAnalyzer(adapter=inspector.adapter, filepath=str(pe_sample))
        rich_result = rich.analyze()
        assert rich_result.get("is_pe") is True
        assert "available" in rich_result

    with create_inspector(str(elf_sample)) as inspector:
        rich = RichHeaderAnalyzer(adapter=inspector.adapter, filepath=str(elf_sample))
        rich_result = rich.analyze()
        assert "available" in rich_result
        assert rich_result.get("is_pe") in {True, False}


def test_function_analyzer_real_variants(samples_dir: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    tiny = samples_dir / "edge_tiny.bin"

    with create_inspector(str(pe_sample)) as inspector:
        analyzer = FunctionAnalyzer(inspector.adapter, inspector.config, str(pe_sample))
        result = analyzer.analyze_functions()
        assert "total_functions" in result
        assert "function_stats" in result

    with create_inspector(str(tiny)) as inspector:
        analyzer = FunctionAnalyzer(inspector.adapter, inspector.config, str(tiny))
        result = analyzer.analyze_functions()
        assert result.get("total_functions") == 0
        assert "error" in result


def test_hashing_analyzers_real_inputs(samples_dir: Path, tmp_path: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    elf_sample = samples_dir / "hello_elf"
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    ssdeep = SSDeepAnalyzer(str(empty_file))
    ssdeep_result = ssdeep.analyze()
    assert "available" in ssdeep_result
    assert ssdeep_result.get("available") is False
    if get_ssdeep() is None and SSDeepAnalyzer.is_available():
        assert ssdeep_result.get("method_used") in {None, "system_binary"}

    with create_inspector(str(pe_sample)) as inspector:
        tlsh = TLSHAnalyzer(inspector.adapter, str(pe_sample))
        tlsh_result = tlsh.analyze()
        assert "available" in tlsh_result
        if TLSH_AVAILABLE:
            assert "binary_tlsh" in tlsh_result
        else:
            assert tlsh_result.get("available") is False

    with create_inspector(str(elf_sample)) as inspector:
        telfhash = TelfhashAnalyzer(inspector.adapter, str(elf_sample))
        telfhash_result = telfhash.analyze()
        assert "available" in telfhash_result
        if TELFHASH_AVAILABLE:
            assert "telfhash" in telfhash_result
        else:
            assert telfhash_result.get("available") is False

    with create_inspector(str(pe_sample)) as inspector:
        telfhash = TelfhashAnalyzer(inspector.adapter, str(pe_sample))
        symbols_result = telfhash.analyze_symbols()
        assert "is_elf" in symbols_result
