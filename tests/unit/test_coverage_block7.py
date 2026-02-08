from __future__ import annotations

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.impfuzzy_analyzer import IMPFUZZY_AVAILABLE, ImpfuzzyAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.telfhash_analyzer import TELFHASH_AVAILABLE, TelfhashAnalyzer

PE_FIXTURE = "samples/fixtures/hello_pe.exe"
ELF_FIXTURE = "samples/fixtures/hello_elf"


def test_authenticode_analyzer_on_fixture() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = AuthenticodeAnalyzer(adapter)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert "has_signature" in result
    assert "signature_valid" in result
    assert "errors" in result


def test_resource_analyzer_on_fixture() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = ResourceAnalyzer(adapter)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert "has_resources" in result
    assert "resources" in result
    assert "statistics" in result


def test_telfhash_analyzer_symbols() -> None:
    r2 = r2pipe.open(ELF_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = TelfhashAnalyzer(adapter, ELF_FIXTURE)
        result = analyzer.analyze_symbols()
    finally:
        r2.quit()

    if TELFHASH_AVAILABLE:
        assert result["available"] is True
        assert "symbol_count" in result
    else:
        assert result["available"] is False
        assert "telfhash library not available" in result["error"]


def test_impfuzzy_analyzer_imports() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = ImpfuzzyAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze_imports()
    finally:
        r2.quit()

    if IMPFUZZY_AVAILABLE:
        assert "import_count" in result
        assert "dll_count" in result
    else:
        assert result["available"] is False
        assert "pyimpfuzzy library not available" in result["error"]
