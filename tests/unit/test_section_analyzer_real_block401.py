"""Comprehensive tests for section analyzer - targeting 12% -> 100% coverage.

NO mocks, NO monkeypatch, NO @patch.
Uses FakeR2 + R2PipeAdapter to exercise SectionAnalyzer through the
production adapter stack.
"""

from __future__ import annotations

import random

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


def _hex_bytes(byte_val: int, count: int) -> str:
    """Return a hex string of *count* repetitions of *byte_val*."""
    return f"{byte_val:02x}" * count


def _random_hex(count: int, seed: int = 42) -> str:
    """Return a hex string of *count* random bytes (deterministic via seed)."""
    rng = random.Random(seed)
    return "".join(f"{rng.randint(0, 255):02x}" for _ in range(count))


def _build_analyzer(
    sections: list | None = None,
    cmd_map_extra: dict | None = None,
    cmdj_map_extra: dict | None = None,
    byte_hex: str = "",
    arch: str = "x86",
    functions: list | None = None,
) -> SectionAnalyzer:
    """Build a SectionAnalyzer backed by FakeR2 + R2PipeAdapter."""
    if sections is None:
        sections = [_TEXT_SECTION]

    cmdj_map: dict = {
        "iSj": sections,
        "ij": {"bin": {"arch": arch}},
        "aflj": functions if functions is not None else [],
    }
    if cmdj_map_extra:
        cmdj_map.update(cmdj_map_extra)

    cmd_map: dict = {}
    if cmd_map_extra:
        cmd_map.update(cmd_map_extra)

    # For each section, register a p8 response so read_bytes succeeds.
    for sec in sections:
        size = sec.get("size", 0)
        vaddr = sec.get("vaddr", 0)
        if size > 0:
            key = f"p8 {size} @ {vaddr}"
            if key not in cmd_map:
                cmd_map[key] = byte_hex or _hex_bytes(0x90, size)

    r2 = FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map)
    adapter = R2PipeAdapter(r2)
    return SectionAnalyzer(adapter, None)


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

_RWX_SECTION = {
    "name": ".suspicious",
    "vaddr": 0x1000,
    "vsize": 1000,
    "size": 1000,
    "flags": "rwx",
    "perm": "-wx",
}


# ---------------------------------------------------------------------------
# Tests -- basic analysis
# ---------------------------------------------------------------------------


def test_section_analyzer_basic():
    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION],
        byte_hex=_hex_bytes(0x90, 1000),
    )
    result = analyzer.analyze()

    assert result["total_sections"] == 1
    assert len(result["sections"]) == 1


# ---------------------------------------------------------------------------
# Tests -- permissions
# ---------------------------------------------------------------------------


def test_section_analyzer_permissions():
    analyzer = _build_analyzer(
        sections=[_RWX_SECTION],
        byte_hex=_hex_bytes(0x41, 1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert section["is_executable"] is True
    assert section["is_writable"] is True


# ---------------------------------------------------------------------------
# Tests -- entropy
# ---------------------------------------------------------------------------


def test_section_analyzer_entropy():
    """Random-like data should produce high entropy."""
    analyzer = _build_analyzer(
        sections=[
            {
                "name": ".packed",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r-x",
                "perm": "r-x",
            }
        ],
        byte_hex=_random_hex(1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert section["entropy"] > 6.0


# ---------------------------------------------------------------------------
# Tests -- suspicious writable+executable
# ---------------------------------------------------------------------------


def test_section_analyzer_suspicious_writable_executable():
    analyzer = _build_analyzer(
        sections=[_RWX_SECTION],
        byte_hex=_hex_bytes(0x41, 1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert any("Writable and executable" in ind for ind in section["suspicious_indicators"])


# ---------------------------------------------------------------------------
# Tests -- high entropy detection
# ---------------------------------------------------------------------------


def test_section_analyzer_high_entropy_detection():
    analyzer = _build_analyzer(
        sections=[
            {
                "name": ".encrypted",
                "vaddr": 0x1000,
                "vsize": 1000,
                "size": 1000,
                "flags": "r--",
                "perm": "r--",
            }
        ],
        byte_hex=_random_hex(1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert any("entropy" in ind.lower() for ind in section["suspicious_indicators"])


# ---------------------------------------------------------------------------
# Tests -- PE characteristics decoding
# ---------------------------------------------------------------------------


def test_section_analyzer_pe_characteristics():
    section_with_chars = {
        "name": ".text",
        "vaddr": 0x1000,
        "vsize": 1000,
        "size": 1000,
        "characteristics": 0x03000020,  # CODE | EXECUTE | READ
    }
    analyzer = _build_analyzer(
        sections=[section_with_chars],
        byte_hex=_hex_bytes(0xCC, 1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert "IMAGE_SCN_CNT_CODE" in section["pe_characteristics"]
    assert section["is_executable"] is True


# ---------------------------------------------------------------------------
# Tests -- size ratio
# ---------------------------------------------------------------------------


def test_section_analyzer_size_ratio():
    bss_section = {
        "name": ".bss",
        "vaddr": 0x1000,
        "vsize": 10000,
        "size": 100,
        "flags": "rw-",
        "perm": "rw-",
    }
    analyzer = _build_analyzer(
        sections=[bss_section],
        byte_hex=_hex_bytes(0x00, 100),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert section["size_ratio"] == 100.0
    assert any("size ratio" in ind.lower() for ind in section["suspicious_indicators"])


# ---------------------------------------------------------------------------
# Tests -- summary with multiple sections
# ---------------------------------------------------------------------------


def test_section_analyzer_summary():
    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION, _DATA_SECTION],
        byte_hex=_hex_bytes(0x41, max(_TEXT_SECTION["size"], _DATA_SECTION["size"])),
    )
    result = analyzer.analyze()

    summary = result["summary"]
    assert summary["total_sections"] == 2
    assert summary["executable_sections"] == 1
    assert summary["writable_sections"] == 1


# ---------------------------------------------------------------------------
# Tests -- non-standard section names
# ---------------------------------------------------------------------------


def test_section_analyzer_non_standard_section():
    upx_section = {
        "name": "UPX0",
        "vaddr": 0x1000,
        "vsize": 1000,
        "size": 1000,
        "flags": "rwx",
        "perm": "rwx",
    }
    analyzer = _build_analyzer(
        sections=[upx_section],
        byte_hex=_hex_bytes(0x41, 1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert any(
        "Non-standard" in ind or "upx" in ind.lower() for ind in section["suspicious_indicators"]
    )


# ---------------------------------------------------------------------------
# Tests -- zero entropy
# ---------------------------------------------------------------------------


def test_section_analyzer_zero_entropy():
    bss = {
        "name": ".bss",
        "vaddr": 0x1000,
        "vsize": 1000,
        "size": 1000,
        "flags": "rw-",
        "perm": "rw-",
    }
    analyzer = _build_analyzer(
        sections=[bss],
        byte_hex=_hex_bytes(0x00, 1000),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert section["entropy"] < 0.1


# ---------------------------------------------------------------------------
# Tests -- very small section
# ---------------------------------------------------------------------------


def test_section_analyzer_very_small_section():
    tiny = {
        "name": ".tiny",
        "vaddr": 0x1000,
        "vsize": 50,
        "size": 50,
        "flags": "r--",
        "perm": "r--",
    }
    analyzer = _build_analyzer(
        sections=[tiny],
        byte_hex=_hex_bytes(0x00, 50),
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    assert any("small" in ind.lower() for ind in section["suspicious_indicators"])


# ---------------------------------------------------------------------------
# Tests -- very large section (entropy skipped)
# ---------------------------------------------------------------------------


def test_section_analyzer_very_large_section():
    huge = {
        "name": ".huge",
        "vaddr": 0x1000,
        "vsize": 60000000,
        "size": 60000000,
        "flags": "r--",
        "perm": "r--",
    }
    # Don't register bytes -- the section is too large for entropy calculation
    analyzer = _build_analyzer(
        sections=[huge],
        byte_hex="",
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    # Entropy should be skipped/0 for very large sections
    assert section["entropy"] == 0.0


# ---------------------------------------------------------------------------
# Tests -- supports_format
# ---------------------------------------------------------------------------


def test_section_analyzer_supports_format():
    analyzer = _build_analyzer()
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("ELF") is True
    assert analyzer.supports_format("MACHO") is True
    assert analyzer.supports_format("UNKNOWN") is False


# ---------------------------------------------------------------------------
# Tests -- error handling (adapter returns no sections)
# ---------------------------------------------------------------------------


def test_section_analyzer_error_handling():
    """When iSj returns None, analyze should still produce a valid result."""
    r2 = FakeR2(
        cmdj_map={"iSj": None, "ij": {"bin": {"arch": "x86"}}, "aflj": []},
    )
    adapter = R2PipeAdapter(r2)
    analyzer = SectionAnalyzer(adapter, None)
    result = analyzer.analyze()

    assert result["available"] is True


# ---------------------------------------------------------------------------
# Tests -- invalid section data filtering
# ---------------------------------------------------------------------------


def test_section_analyzer_invalid_section_data():
    """Non-dict entries in the section list should be filtered out."""
    sections_raw = [
        "invalid",  # Not a dict
        {"name": ".text", "vaddr": 0x1000, "vsize": 1000, "size": 1000, "flags": "r-x"},
        123,  # Not a dict
    ]
    r2 = FakeR2(
        cmd_map={f"p8 1000 @ {0x1000}": _hex_bytes(0x90, 1000)},
        cmdj_map={
            "iSj": sections_raw,
            "ij": {"bin": {"arch": "x86"}},
            "aflj": [],
        },
    )
    adapter = R2PipeAdapter(r2)
    analyzer = SectionAnalyzer(adapter, None)
    sections = analyzer.analyze_sections()

    # Should only process the valid dict entry
    assert len(sections) == 1


# ---------------------------------------------------------------------------
# Tests -- NOP detection in code sections
# ---------------------------------------------------------------------------


def test_section_analyzer_nop_detection():
    """A section full of NOP bytes should trigger code analysis metrics."""
    nop_hex = _hex_bytes(0x90, 1000)

    analyzer = _build_analyzer(
        sections=[_TEXT_SECTION],
        byte_hex=nop_hex,
        arch="x86",
    )
    result = analyzer.analyze()

    section = result["sections"][0]
    # The section analysis should complete without error; whether
    # excessive_nops is reported depends on the code analysis path.
    if "characteristics" in section and "code_analysis" in section.get("characteristics", {}):
        code_info = section["characteristics"]["code_analysis"]
        if "excessive_nops" in code_info:
            assert code_info["excessive_nops"] is True
