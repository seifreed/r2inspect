from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.factory import create_inspector
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.simhash_analyzer import NO_FEATURES_ERROR, SIMHASH_AVAILABLE, SimHashAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer

pytestmark = pytest.mark.requires_r2


def test_function_analyzer_real_and_no_functions(samples_dir: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    tiny_sample = samples_dir / "edge_tiny.bin"

    with create_inspector(str(pe_sample)) as inspector:
        analyzer = FunctionAnalyzer(inspector.adapter, inspector.config, str(pe_sample))
        result = analyzer.analyze_functions()
        assert isinstance(result, dict)
        assert result["total_functions"] >= 0
        assert "function_stats" in result

        if result.get("machoc_hashes"):
            summary = analyzer.generate_machoc_summary(result)
            assert summary["total_functions_hashed"] >= 0

    with create_inspector(str(tiny_sample)) as inspector:
        analyzer = FunctionAnalyzer(inspector.adapter, inspector.config, str(tiny_sample))
        result = analyzer.analyze_functions()
        assert result["total_functions"] == 0
        assert "error" in result
        summary = analyzer.generate_machoc_summary(result)
        assert "error" in summary


def test_rich_header_and_resource_analyzers_real(samples_dir: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    elf_sample = samples_dir / "hello_elf"

    with create_inspector(str(pe_sample)) as inspector:
        rich = RichHeaderAnalyzer(adapter=inspector.adapter, filepath=str(pe_sample))
        rich_result = rich.analyze()
        assert rich_result["is_pe"] is True

        resources = ResourceAnalyzer(inspector.adapter)
        resource_result = resources.analyze()
        assert isinstance(resource_result, dict)
        assert "resources" in resource_result

        assert resources._read_resource_as_string(0, 0) is None

    with create_inspector(str(elf_sample)) as inspector:
        rich = RichHeaderAnalyzer(adapter=inspector.adapter, filepath=str(elf_sample))
        rich_result = rich.analyze()
        if rich_result["is_pe"] is False:
            assert rich_result["error"] == "File is not a PE binary"
        else:
            assert rich_result["error"] in (None, "Rich Header not found")


def test_hashing_analyzers_real_and_validation_errors(samples_dir: Path, tmp_path: Path) -> None:
    pe_sample = samples_dir / "hello_pe.exe"
    elf_sample = samples_dir / "hello_elf"

    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    missing_file = tmp_path / "missing.bin"
    bad_dir = tmp_path / "dir"
    bad_dir.mkdir()

    ssdeep_empty = SSDeepAnalyzer(str(empty_file))
    ssdeep_result = ssdeep_empty.analyze()
    assert ssdeep_result["available"] is False
    assert "File too small" in (ssdeep_result["error"] or "")

    tlsh_bad = TLSHAnalyzer(None, str(bad_dir))
    tlsh_bad_result = tlsh_bad.analyze()
    assert "Path is not a regular file" in (tlsh_bad_result["error"] or "")

    telfhash_missing = TelfhashAnalyzer(None, str(missing_file))
    telfhash_missing_result = telfhash_missing.analyze()
    assert "File does not exist" in (telfhash_missing_result["error"] or "")

    with create_inspector(str(elf_sample)) as inspector:
        telfhash = TelfhashAnalyzer(inspector.adapter, str(elf_sample))
        telfhash_result = telfhash.analyze()
        assert "error" in telfhash_result

    with create_inspector(str(pe_sample)) as inspector:
        tlsh = TLSHAnalyzer(inspector.adapter, str(pe_sample))
        tlsh_result = tlsh.analyze()
        assert "error" in tlsh_result

        simhash = SimHashAnalyzer(inspector.adapter, str(pe_sample))
        simhash_result = simhash.analyze()
        if SIMHASH_AVAILABLE:
            assert simhash_result["error"] in (None, NO_FEATURES_ERROR)
        else:
            assert "library not available" in (simhash_result["error"] or "")
