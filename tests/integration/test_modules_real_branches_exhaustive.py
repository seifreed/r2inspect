from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.factory import create_inspector

pytestmark = pytest.mark.requires_r2


def _assert_dict(value: object) -> None:
    assert isinstance(value, dict)


def _assert_list(value: object) -> None:
    assert isinstance(value, list)


@pytest.mark.parametrize(
    "sample_name",
    [
        "hello_pe.exe",
        "hello_elf",
        "hello_macho",
    ],
)
def test_full_analyzer_surface_real(samples_dir: Path, sample_name: str) -> None:
    sample = samples_dir / sample_name
    with create_inspector(str(sample)) as inspector:
        _assert_dict(inspector.get_file_info())
        _assert_dict(inspector.get_pe_info())
        _assert_dict(inspector.get_elf_info())
        _assert_dict(inspector.get_macho_info())
        _assert_list(inspector.get_strings())
        _assert_dict(inspector.get_security_features())
        _assert_list(inspector.get_imports())
        _assert_list(inspector.get_exports())
        _assert_list(inspector.get_sections())
        _assert_dict(inspector.detect_packer())
        _assert_dict(inspector.detect_crypto())
        _assert_dict(inspector.detect_anti_analysis())
        _assert_dict(inspector.detect_compiler())
        _assert_list(inspector.run_yara_rules())
        _assert_list(inspector.search_xor("ABC"))
        _assert_dict(inspector.analyze_functions())
        _assert_dict(inspector.analyze_ssdeep())
        _assert_dict(inspector.analyze_tlsh())
        _assert_dict(inspector.analyze_telfhash())
        _assert_dict(inspector.analyze_rich_header())
        _assert_dict(inspector.analyze_impfuzzy())
        _assert_dict(inspector.analyze_ccbhash())
        _assert_dict(inspector.analyze_binlex())
        _assert_dict(inspector.analyze_binbloom())
        _assert_dict(inspector.analyze_simhash())
        _assert_dict(inspector.analyze_bindiff())
        results = inspector.analyze(
            batch_mode=True,
            detect_packer=True,
            detect_crypto=True,
            analyze_functions=True,
        )
        _assert_dict(results)


@pytest.mark.parametrize(
    "sample_name",
    [
        "edge_bad_pe.bin",
        "edge_tiny.bin",
    ],
)
def test_edge_case_analyzers_real(samples_dir: Path, sample_name: str) -> None:
    sample = samples_dir / sample_name
    with create_inspector(str(sample)) as inspector:
        _assert_dict(inspector.get_file_info())
        _assert_dict(inspector.get_pe_info())
        _assert_list(inspector.get_sections())
        _assert_dict(inspector.analyze_rich_header())
        _assert_dict(inspector.analyze_telfhash())
