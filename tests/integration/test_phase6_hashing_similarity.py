from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.binlex_analyzer import BinlexAnalyzer
from r2inspect.modules.ccbhash_analyzer import NO_FUNCTIONS_FOUND, CCBHashAnalyzer
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer
from r2inspect.utils.ssdeep_loader import get_ssdeep

pytestmark = pytest.mark.requires_r2

PE_FIXTURE = "samples/fixtures/hello_pe.exe"
ELF_FIXTURE = "samples/fixtures/hello_elf"


def _open_adapter(path: str) -> tuple[Any, R2PipeAdapter]:
    r2 = r2pipe.open(path)
    return r2, R2PipeAdapter(r2)


def test_ssdeep_analyzer_real_binary() -> None:
    analyzer = SSDeepAnalyzer(PE_FIXTURE)
    result = analyzer.analyze()

    if SSDeepAnalyzer.is_available():
        assert result["available"] is True
        assert result["hash_value"]
        if get_ssdeep() is None:
            assert result["method_used"] == "system_binary"
        else:
            assert result["method_used"] in {"python_library", "system_binary"}
    else:
        assert result["available"] is False
        assert "SSDeep not available" in result["error"]


def test_tlsh_analyzer_library_gate() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = TLSHAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze()
    finally:
        r2.quit()

    if TLSHAnalyzer.is_available():
        assert result["available"] is True
        assert result["hash_value"]
    else:
        assert result["available"] is False
        assert "TLSH library not available" in result["error"]


def test_telfhash_analyzer_library_gate() -> None:
    r2, adapter = _open_adapter(ELF_FIXTURE)
    try:
        analyzer = TelfhashAnalyzer(adapter, ELF_FIXTURE)
        result = analyzer.analyze()
    finally:
        r2.quit()

    if TelfhashAnalyzer.is_available():
        assert result["available"] is True
        assert result["hash_value"]
    else:
        assert result["available"] is False
        assert "telfhash library not available" in result["error"]


def test_impfuzzy_analyzer_library_gate() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = ImpfuzzyAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze()
    finally:
        r2.quit()

    if ImpfuzzyAnalyzer.is_available():
        assert result["available"] is True
        assert result["hash_value"]
    else:
        assert result["available"] is False
        assert "pyimpfuzzy library not available" in result["error"]


def test_simhash_analyzer_basic() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = SimHashAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze()
        detailed = analyzer.analyze_detailed()
    finally:
        r2.quit()

    assert result["available"] is True
    assert isinstance(result["hash_value"], str)
    assert result["hash_value"].startswith("0x")
    assert detailed["available"] is True
    assert detailed.get("combined_simhash")


def test_binbloom_analyzer_basic() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = BinbloomAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze(capacity=64, error_rate=0.01)
    finally:
        r2.quit()

    if not BLOOM_AVAILABLE:
        assert result["available"] is False
        assert "pybloom-live" in result["error"]
        return

    if result["available"]:
        assert isinstance(result["function_blooms"], dict)
        assert isinstance(result["function_signatures"], dict)
        assert result["binary_signature"] is not None
    else:
        assert result["error"] in {
            "No functions found in binary",
            "No functions could be analyzed for Binbloom",
        }


def test_binlex_analyzer_basic() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = BinlexAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze(ngram_sizes=[2])
    finally:
        r2.quit()

    assert "available" in result
    assert "function_signatures" in result
    assert "binary_signature" in result
    if result["available"]:
        assert isinstance(result["function_signatures"], dict)
    else:
        assert result["error"] in {
            "No functions found in binary",
            "No functions could be analyzed for Binlex",
        }


def test_bindiff_analyzer_basic() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = BinDiffAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["comparison_ready"] is True
    assert "structural_features" in result
    assert "signatures" in result


def test_ccbhash_analyzer_error_path() -> None:
    r2, adapter = _open_adapter(PE_FIXTURE)
    try:
        analyzer = CCBHashAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    if result["hash_value"] is None:
        assert result["error"] == NO_FUNCTIONS_FOUND
