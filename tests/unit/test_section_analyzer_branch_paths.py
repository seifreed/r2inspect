"""Branch-path tests for r2inspect/modules/section_analyzer.py."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.section_analyzer import SectionAnalyzer


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class _TypedConfig:
    pass


class StubConfig:
    typed_config = _TypedConfig()


class StubAdapter:
    """Minimal adapter that returns configurable data."""

    def __init__(
        self,
        sections: list | None = None,
        read_bytes_data: bytes = b"",
        file_info: dict | None = None,
    ) -> None:
        self._sections = sections or []
        self._read_bytes_data = read_bytes_data
        self._file_info = file_info or {}

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

    def read_bytes(self, addr: int, size: int) -> bytes:
        return self._read_bytes_data

    def get_file_info(self) -> dict[str, Any]:
        return self._file_info


class RaisingReadBytesAdapter:
    """Adapter whose read_bytes raises."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "vaddr": 0x1000, "vsize": 0x100, "size": 0x100, "flags": "r-x"}]

    def read_bytes(self, addr: int, size: int) -> bytes:
        raise OSError("read failed")

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "x86"}


class X86Adapter:
    """Adapter that returns x86 arch and NOP-heavy bytes."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 0x200,
                "size": 0x200,
                "flags": "r-x",
                "perm": "r-x",
            }
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b"\x90" * size

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "x86"}


class NonX86Adapter:
    """Adapter returning a non-x86 architecture."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x100, "size": 0x100, "flags": "r-x"}
        ]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b"\x00" * size

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "arm"}


# ---------------------------------------------------------------------------
# analyze_sections - non-dict section triggers warning (line 64)
# ---------------------------------------------------------------------------


def test_analyze_sections_skips_non_dict_entries():
    adapter = StubAdapter(sections=["not_a_dict", {"name": ".text", "vaddr": 0, "vsize": 100, "size": 100, "flags": "r-x"}])
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    sections = analyzer.analyze_sections()
    # Only the dict section is processed
    assert len(sections) == 1
    assert sections[0]["name"] == ".text"


# ---------------------------------------------------------------------------
# _calculate_entropy - empty read_bytes returns 0.0 (line 149)
# ---------------------------------------------------------------------------


def test_calculate_entropy_returns_zero_when_read_bytes_empty():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0x100}
    adapter = StubAdapter(read_bytes_data=b"")
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    entropy = analyzer._calculate_entropy(section)
    assert entropy == 0.0


def test_calculate_entropy_returns_zero_when_size_is_zero():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0}
    adapter = StubAdapter(read_bytes_data=b"data")
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    entropy = analyzer._calculate_entropy(section)
    assert entropy == 0.0


def test_calculate_entropy_returns_zero_on_read_exception():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0x100}
    analyzer = SectionAnalyzer(adapter=RaisingReadBytesAdapter(), config=StubConfig())
    entropy = analyzer._calculate_entropy(section)
    assert entropy == 0.0


def test_calculate_entropy_nonzero_with_real_data():
    section = {"name": ".text", "vaddr": 0x1000, "size": 256}
    adapter = StubAdapter(read_bytes_data=bytes(range(256)))
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    entropy = analyzer._calculate_entropy(section)
    assert entropy > 0.0


# ---------------------------------------------------------------------------
# _check_size_indicators - very small section (line 248)
# ---------------------------------------------------------------------------


def test_check_size_indicators_very_small_section():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    indicators = analyzer._check_size_indicators(vsize=50, raw_size=50)
    assert any("small" in i.lower() for i in indicators)


def test_check_size_indicators_large_virtual_ratio():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    indicators = analyzer._check_size_indicators(vsize=10000, raw_size=100)
    assert any("ratio" in i.lower() or "larger" in i.lower() for i in indicators)


def test_check_size_indicators_very_large_section():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    indicators = analyzer._check_size_indicators(vsize=60000000, raw_size=60000000)
    assert any("large" in i.lower() for i in indicators)


def test_check_size_indicators_no_indicators_for_normal_section():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    indicators = analyzer._check_size_indicators(vsize=0x1000, raw_size=0x1000)
    assert len(indicators) == 0


# ---------------------------------------------------------------------------
# _check_entropy_anomaly exception (lines 340-341)
# ---------------------------------------------------------------------------


def test_check_entropy_anomaly_does_not_raise_on_malformed_range():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    characteristics = {"expected_entropy": "not-a-valid-range"}
    analysis = {"entropy": 5.0}
    # Should not raise; ValueError is caught internally
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert "entropy_anomaly" not in characteristics


def test_check_entropy_anomaly_variable_returns_early():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    characteristics = {"expected_entropy": "Variable"}
    analysis = {"entropy": 9.9}
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert "entropy_anomaly" not in characteristics


def test_check_entropy_anomaly_marks_anomaly():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    characteristics = {"expected_entropy": "1.0-3.0"}
    analysis = {"entropy": 7.5}
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert characteristics.get("entropy_anomaly") is True


# ---------------------------------------------------------------------------
# _analyze_code_section - size == 0 early return (line 352)
# ---------------------------------------------------------------------------


def test_analyze_code_section_returns_empty_when_size_zero():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0}
    adapter = StubAdapter()
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    result = analyzer._analyze_code_section(section)
    assert result == {}


# ---------------------------------------------------------------------------
# _get_functions_in_section - size <= 0 (line 384)
# ---------------------------------------------------------------------------


def test_get_functions_in_section_returns_empty_when_size_nonpositive():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    result = analyzer._get_functions_in_section(0x1000, 0)
    assert result == []


def test_get_functions_in_section_filters_by_address_range():
    analyzer = SectionAnalyzer(adapter=StubAdapter(), config=StubConfig())
    # Inject functions cache directly
    analyzer._functions_cache = [
        {"offset": 0x1000},
        {"offset": 0x2000},
        {"addr": 0x1500},
        "not_a_dict",
    ]
    result = analyzer._get_functions_in_section(0x1000, 0x1000)
    # Should include 0x1000 and 0x1500 (addr key), not 0x2000
    assert any(f.get("offset") == 0x1000 for f in result)
    assert any(f.get("addr") == 0x1500 for f in result)
    assert not any(f.get("offset") == 0x2000 for f in result)


# ---------------------------------------------------------------------------
# _count_nops_in_section - non-x86 arch returns (0, 0) (line 408)
# ---------------------------------------------------------------------------


def test_count_nops_in_section_returns_zero_for_non_x86_arch():
    adapter = NonX86Adapter()
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 0x100)
    assert nop_count == 0
    assert sample_size == 0


def test_count_nops_in_section_returns_zero_when_size_zero():
    analyzer = SectionAnalyzer(adapter=X86Adapter(), config=StubConfig())
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 0)
    assert nop_count == 0
    assert sample_size == 0


def test_count_nops_in_section_returns_zero_when_no_arch():
    adapter = StubAdapter(file_info={})
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 0x100)
    assert nop_count == 0
    assert sample_size == 0


def test_count_nops_in_section_counts_nops_for_x86(tmp_path):
    adapter = X86Adapter()
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 256)
    assert nop_count == 256
    assert sample_size == 256


def test_count_nops_in_section_returns_zero_when_read_bytes_empty():
    adapter = StubAdapter(read_bytes_data=b"", file_info={"arch": "x86"})
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 256)
    assert nop_count == 0
    assert sample_size == 0


# ---------------------------------------------------------------------------
# _analyze_code_section - excessive nops (lines 375, 377-378)
# ---------------------------------------------------------------------------


def test_analyze_code_section_detects_excessive_nops():
    adapter = X86Adapter()
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    section = {"name": ".text", "vaddr": 0x1000, "size": 256}
    result = analyzer._analyze_code_section(section)
    assert "nop_count" in result
    assert result.get("nop_ratio") == 1.0
    assert result.get("excessive_nops") is True


# ---------------------------------------------------------------------------
# _update_summary_for_section - high entropy counts (lines 449-450)
# ---------------------------------------------------------------------------


def test_update_summary_for_section_counts_high_entropy():
    adapter = StubAdapter()
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    summary = {
        "total_sections": 0,
        "executable_sections": 0,
        "writable_sections": 0,
        "suspicious_sections": 0,
        "high_entropy_sections": 0,
        "avg_entropy": 0.0,
        "section_flags_summary": {},
    }
    flag_counts: dict[str, int] = {}
    section = {
        "is_executable": True,
        "is_writable": False,
        "suspicious_indicators": ["High entropy"],
        "entropy": 7.5,
        "flags": "r-x",
    }
    entropy = analyzer._update_summary_for_section(summary, section, flag_counts)
    assert summary["executable_sections"] == 1
    assert summary["suspicious_sections"] == 1
    assert summary["high_entropy_sections"] == 1
    assert entropy == 7.5
    assert flag_counts.get("r-x") == 1


def test_update_summary_for_section_no_indicators():
    adapter = StubAdapter()
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    summary = {
        "executable_sections": 0,
        "writable_sections": 0,
        "suspicious_sections": 0,
        "high_entropy_sections": 0,
    }
    flag_counts: dict[str, int] = {}
    section = {
        "is_executable": False,
        "is_writable": True,
        "suspicious_indicators": [],
        "entropy": 3.0,
        "flags": "rw-",
    }
    entropy = analyzer._update_summary_for_section(summary, section, flag_counts)
    assert summary["writable_sections"] == 1
    assert summary["suspicious_sections"] == 0
    assert summary["high_entropy_sections"] == 0
    assert entropy == 3.0


# ---------------------------------------------------------------------------
# Full analyze flow
# ---------------------------------------------------------------------------


def test_analyze_returns_expected_structure():
    adapter = StubAdapter(
        sections=[{"name": ".text", "vaddr": 0x1000, "vsize": 0x100, "size": 0x100, "flags": "r-x"}],
        read_bytes_data=bytes(range(256)),
    )
    analyzer = SectionAnalyzer(adapter=adapter, config=StubConfig())
    result = analyzer.analyze()
    assert "sections" in result
    assert "summary" in result
    assert "total_sections" in result
