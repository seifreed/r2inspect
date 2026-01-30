from __future__ import annotations

from pathlib import Path

import pytest
import r2pipe

from r2inspect.config import Config
from r2inspect.modules.elf_analyzer import ELFAnalyzer
from r2inspect.modules.macho_analyzer import MachOAnalyzer
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer
from r2inspect.modules.pe_analyzer import PEAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer

pytestmark = pytest.mark.requires_r2

FIXTURES = {
    "hello_macho": "samples/fixtures/hello_macho",
    "hello_pe": "samples/fixtures/hello_pe.exe",
    "hello_elf": "samples/fixtures/hello_elf",
}


def _config(tmp_path: Path) -> Config:
    return Config(str(tmp_path / "r2inspect_phase4.json"))


def test_pe_analyzer_basic(tmp_path: Path) -> None:
    r2 = r2pipe.open(FIXTURES["hello_pe"])
    try:
        analyzer = PEAnalyzer(r2, _config(tmp_path), filepath=FIXTURES["hello_pe"])
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    assert result["format"] in {"PE", "PE32", "PE32+"}
    assert result["bits"] in {32, 64}
    assert result["architecture"] != "Unknown"
    assert isinstance(result["security_features"], dict)
    assert isinstance(result["imphash"], str)


def test_elf_analyzer_basic(tmp_path: Path) -> None:
    r2 = r2pipe.open(FIXTURES["hello_elf"])
    try:
        analyzer = ELFAnalyzer(r2, _config(tmp_path))
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    assert result["bits"] in {32, 64}
    assert isinstance(result["sections"], list)
    assert isinstance(result["program_headers"], list)
    assert result["sections"]
    assert result["program_headers"]
    assert isinstance(result["security_features"], dict)


def test_macho_analyzer_basic(tmp_path: Path) -> None:
    r2 = r2pipe.open(FIXTURES["hello_macho"])
    try:
        analyzer = MachOAnalyzer(r2, _config(tmp_path))
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert result["available"] is True
    assert result["bits"] in {32, 64}
    assert isinstance(result["load_commands"], list)
    assert isinstance(result["sections"], list)
    assert result["load_commands"]
    assert result["sections"]
    assert isinstance(result["security_features"], dict)


def test_rich_header_analyzer_pe_and_non_pe(tmp_path: Path) -> None:
    r2_pe = r2pipe.open(FIXTURES["hello_pe"])
    try:
        analyzer = RichHeaderAnalyzer(r2_pe, FIXTURES["hello_pe"])
        result = analyzer.analyze()
    finally:
        r2_pe.quit()

    assert result["is_pe"] is True
    if result["available"]:
        assert result["rich_header"] is not None
        assert result["xor_key"] is not None
        assert result["checksum"] is not None
        assert result["method_used"] in {"pefile", "r2pipe"}
    else:
        assert result["error"] == "Rich Header not found"

    r2_elf = r2pipe.open(FIXTURES["hello_elf"])
    try:
        analyzer_non_pe = RichHeaderAnalyzer(r2_elf, FIXTURES["hello_elf"])
        result_non_pe = analyzer_non_pe.analyze()
    finally:
        r2_elf.quit()

    assert result_non_pe["available"] is False
    assert result_non_pe["error"] in {"File is not a PE binary", "Rich Header not found"}


def test_overlay_analyzer_no_overlay(tmp_path: Path) -> None:
    r2 = r2pipe.open(FIXTURES["hello_pe"])
    try:
        result = OverlayAnalyzer(r2).analyze()
    finally:
        r2.quit()

    assert isinstance(result["has_overlay"], bool)
    if result["has_overlay"]:
        assert result["overlay_size"] > 0
        assert result["overlay_offset"] > 0
    else:
        assert result["overlay_size"] == 0
