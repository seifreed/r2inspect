from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.factory import create_inspector
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer

pytestmark = pytest.mark.requires_r2


def test_resource_analyzer_error_paths_real(samples_dir: Path) -> None:
    bad_pe = samples_dir / "edge_bad_pe.bin"
    tiny = samples_dir / "edge_tiny.bin"

    for sample in (bad_pe, tiny):
        with create_inspector(str(sample)) as inspector:
            result = ResourceAnalyzer(inspector.adapter).analyze()
            assert "available" in result
            assert "has_resources" in result
            assert "resources" in result


def test_rich_header_analyzer_non_pe_and_malformed_real(samples_dir: Path) -> None:
    elf_sample = samples_dir / "hello_elf"
    bad_pe = samples_dir / "edge_bad_pe.bin"

    with create_inspector(str(elf_sample)) as inspector:
        result = RichHeaderAnalyzer(adapter=inspector.adapter, filepath=str(elf_sample)).analyze()
        assert result.get("available") is False
        assert "error" in result

    with create_inspector(str(bad_pe)) as inspector:
        result = RichHeaderAnalyzer(adapter=inspector.adapter, filepath=str(bad_pe)).analyze()
        assert "available" in result
        assert "error" in result or result.get("available") is True


def test_function_analyzer_error_path_real(samples_dir: Path) -> None:
    tiny = samples_dir / "edge_tiny.bin"

    with create_inspector(str(tiny)) as inspector:
        analyzer = FunctionAnalyzer(inspector.adapter, inspector.config, None)
        result = analyzer.analyze_functions()
        assert result.get("total_functions") == 0
        assert "error" in result
