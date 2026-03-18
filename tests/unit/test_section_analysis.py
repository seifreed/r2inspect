"""Section analysis tests -- real code, no mocks, no monkeypatch, no @patch.

Uses FakeR2 + R2PipeAdapter to exercise SectionAnalyzer through the
production adapter stack.  Section data arrives via the ``iSj`` r2 command;
byte reads use ``p8 <size> @ <addr>``; architecture info comes from ``ij``.
"""

from __future__ import annotations

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.section_analyzer import SectionAnalyzer


# ---------------------------------------------------------------------------
# FakeR2 -- deterministic stand-in for r2pipe
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in that returns pre-configured responses."""

    def __init__(
        self,
        cmd_map: dict | None = None,
        cmdj_map: dict | None = None,
    ) -> None:
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return self._cmd_map.get(command, "")

    def cmdj(self, command: str):
        return self._cmdj_map.get(command)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEXT_SECTION = {
    "name": ".text",
    "vaddr": 0x1000,
    "vsize": 1000,
    "size": 1000,
    "flags": "r-x",
    "perm": "r-x",
}

_DATA_SECTION = {
    "name": ".data",
    "vaddr": 0x2000,
    "vsize": 500,
    "size": 500,
    "flags": "rw-",
    "perm": "rw-",
}


def _hex_bytes(byte_val: int, count: int) -> str:
    """Return a hex string of *count* repetitions of *byte_val*."""
    return f"{byte_val:02x}" * count


def _build_analyzer(
    sections: list | None = None,
    byte_hex: str = "",
    arch: str = "x86",
) -> SectionAnalyzer:
    """Build a SectionAnalyzer backed by FakeR2 + R2PipeAdapter."""
    sections = sections if sections is not None else [_TEXT_SECTION]
    cmdj_map: dict = {
        "iSj": sections,
        "ij": {"bin": {"arch": arch}},
    }
    cmd_map: dict = {}
    # For each section, register a p8 response so read_bytes succeeds.
    for sec in sections:
        size = sec.get("size", 0)
        vaddr = sec.get("vaddr", 0)
        if size > 0:
            key = f"p8 {size} @ {vaddr}"
            cmd_map[key] = byte_hex or _hex_bytes(0x90, size)

    r2 = FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map)
    adapter = R2PipeAdapter(r2)
    return SectionAnalyzer(adapter, None)


# ---------------------------------------------------------------------------
# Tests -- category / description / format support
# ---------------------------------------------------------------------------


def test_section_analyzer_category():
    analyzer = _build_analyzer()
    assert analyzer.get_category() == "metadata"


def test_section_analyzer_description():
    analyzer = _build_analyzer()
    description = analyzer.get_description()
    assert isinstance(description, str)
    assert len(description) > 0


def test_section_analyzer_supports_pe():
    analyzer = _build_analyzer()
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True


def test_section_analyzer_supports_elf():
    analyzer = _build_analyzer()
    assert analyzer.supports_format("ELF") is True


def test_section_analyzer_supports_macho():
    analyzer = _build_analyzer()
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("MACHO") is True


def test_section_analyzer_unsupported_format():
    analyzer = _build_analyzer()
    assert analyzer.supports_format("UNKNOWN") is False


# ---------------------------------------------------------------------------
# Tests -- analyze() top-level structure
# ---------------------------------------------------------------------------


def test_section_analysis_structure():
    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION],
        byte_hex=_hex_bytes(0x90, 1000),
    )
    result = analyzer.analyze()

    assert "sections" in result
    assert "summary" in result
    assert "total_sections" in result


def test_section_fields_present():
    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION],
        byte_hex=_hex_bytes(0x90, 1000),
    )
    result = analyzer.analyze()

    assert result.get("sections"), "Expected at least one section"
    section = result["sections"][0]
    assert "name" in section
    assert "entropy" in section
    assert "is_executable" in section
    assert "is_writable" in section
    assert "is_readable" in section


def test_section_summary_fields():
    # Use zero bytes so entropy is 0.0
    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION],
        byte_hex=_hex_bytes(0x00, 1000),
    )
    summary = analyzer.get_section_summary()

    assert "total_sections" in summary
    assert "executable_sections" in summary
    assert "writable_sections" in summary
    assert "suspicious_sections" in summary
    assert "high_entropy_sections" in summary
    assert "avg_entropy" in summary


# ---------------------------------------------------------------------------
# Tests -- empty section list
# ---------------------------------------------------------------------------


def test_section_empty_list():
    analyzer = _build_analyzer(sections=[])
    sections = analyzer.analyze_sections()
    assert sections == []


# ---------------------------------------------------------------------------
# Tests -- PE characteristics decoding
# ---------------------------------------------------------------------------


def test_section_decode_pe_characteristics():
    analyzer = _build_analyzer()
    flags = analyzer._decode_pe_characteristics(0x20000020)

    assert "IMAGE_SCN_CNT_CODE" in flags
    assert "IMAGE_SCN_MEM_NOT_PAGED" in flags


# ---------------------------------------------------------------------------
# Tests -- size ratio calculation
# ---------------------------------------------------------------------------


def test_section_calculate_size_ratio():
    analyzer = _build_analyzer()
    analysis = {"virtual_size": 5000, "raw_size": 1000}
    ratio = analyzer._calculate_size_ratio(analysis)
    assert ratio == 5.0


def test_section_calculate_size_ratio_zero():
    analyzer = _build_analyzer()
    analysis = {"virtual_size": 1000, "raw_size": 0}
    ratio = analyzer._calculate_size_ratio(analysis)
    assert ratio == 0.0


# ---------------------------------------------------------------------------
# Tests -- standard sections list
# ---------------------------------------------------------------------------


def test_section_standard_sections():
    analyzer = _build_analyzer()
    assert ".text" in analyzer.standard_sections
    assert ".data" in analyzer.standard_sections
    assert ".rdata" in analyzer.standard_sections


# ---------------------------------------------------------------------------
# Tests -- entropy indicators
# ---------------------------------------------------------------------------


def test_section_entropy_indicator_high():
    analyzer = _build_analyzer()
    indicators = analyzer._check_entropy_indicators(7.6)
    assert len(indicators) > 0
    assert any("High entropy" in ind for ind in indicators)


def test_section_entropy_indicator_moderate():
    analyzer = _build_analyzer()
    indicators = analyzer._check_entropy_indicators(7.2)
    assert len(indicators) > 0
    assert any("entropy" in ind.lower() for ind in indicators)


# ---------------------------------------------------------------------------
# Tests -- permission indicators
# ---------------------------------------------------------------------------


def test_section_permission_indicators_wx():
    analyzer = _build_analyzer()
    analysis = {"is_writable": True, "is_executable": True, "entropy": 5.0}
    indicators = analyzer._check_permission_indicators(analysis)
    assert any("Writable and executable" in ind for ind in indicators)


# ---------------------------------------------------------------------------
# Tests -- size indicators
# ---------------------------------------------------------------------------


def test_section_size_indicators_large_ratio():
    analyzer = _build_analyzer()
    indicators = analyzer._check_size_indicators(10000, 1000)
    assert len(indicators) > 0


def test_section_size_indicators_small():
    analyzer = _build_analyzer()
    indicators = analyzer._check_size_indicators(50, 50)
    assert any("Very small section" in ind for ind in indicators)


# ---------------------------------------------------------------------------
# Tests -- multi-section analysis
# ---------------------------------------------------------------------------


def test_section_analysis_multiple_sections():
    """Verify analyze() handles multiple sections correctly."""
    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION, _DATA_SECTION],
        byte_hex=_hex_bytes(0x41, max(_TEXT_SECTION["size"], _DATA_SECTION["size"])),
    )
    result = analyzer.analyze()

    assert result["total_sections"] == 2
    names = [s["name"] for s in result["sections"]]
    assert ".text" in names
    assert ".data" in names


def test_section_permissions_writable_section():
    """A section with 'rw-' flags should be writable but not executable."""
    analyzer = _build_analyzer(
        sections=[_DATA_SECTION],
        byte_hex=_hex_bytes(0x00, 500),
    )
    result = analyzer.analyze()
    section = result["sections"][0]
    assert section["is_writable"] is True
    assert section["is_executable"] is False
    assert section["is_readable"] is True
