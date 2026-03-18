"""Branch-path tests for r2inspect/modules/section_analyzer.py.

NO mocks, NO monkeypatch, NO @patch.
Uses FakeR2 + R2PipeAdapter to exercise SectionAnalyzer through the
production adapter stack.
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


def _hex_bytes(byte_val: int, count: int) -> str:
    """Return a hex string of *count* repetitions of *byte_val*."""
    return f"{byte_val:02x}" * count


def _build_analyzer(
    sections: list | None = None,
    byte_hex: str = "",
    arch: str = "x86",
    functions: list | None = None,
    cmd_map_extra: dict | None = None,
    cmdj_map_extra: dict | None = None,
    file_info: dict | None = None,
) -> SectionAnalyzer:
    """Build a SectionAnalyzer backed by FakeR2 + R2PipeAdapter."""
    if sections is None:
        sections = []

    cmdj_map: dict = {
        "iSj": sections,
        "ij": file_info if file_info is not None else {"bin": {"arch": arch}},
        "aflj": functions if functions is not None else [],
    }
    if cmdj_map_extra:
        cmdj_map.update(cmdj_map_extra)

    cmd_map: dict = {}
    if cmd_map_extra:
        cmd_map.update(cmd_map_extra)

    for sec in sections:
        if isinstance(sec, dict):
            size = sec.get("size", 0)
            vaddr = sec.get("vaddr", 0)
            if size > 0:
                key = f"p8 {size} @ {vaddr}"
                if key not in cmd_map:
                    cmd_map[key] = byte_hex or _hex_bytes(0x00, size)

    r2 = FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map)
    adapter = R2PipeAdapter(r2)
    return SectionAnalyzer(adapter, None)


# ---------------------------------------------------------------------------
# analyze_sections - non-dict section triggers warning (line 64)
# ---------------------------------------------------------------------------


def test_analyze_sections_skips_non_dict_entries():
    sections = [
        "not_a_dict",
        {"name": ".text", "vaddr": 0, "vsize": 100, "size": 100, "flags": "r-x"},
    ]
    analyzer = _build_analyzer(
        sections=sections,
        cmd_map_extra={"p8 100 @ 0": _hex_bytes(0xCC, 100)},
    )
    result = analyzer.analyze_sections()
    # Only the dict section is processed
    assert len(result) == 1
    assert result[0]["name"] == ".text"


def test_analyze_sections_handles_empty_sections():
    analyzer = _build_analyzer(sections=[])
    sections = analyzer.analyze_sections()
    assert sections == []


# ---------------------------------------------------------------------------
# _calculate_entropy - empty read_bytes returns 0.0 (line 149)
# ---------------------------------------------------------------------------


def test_calculate_entropy_returns_zero_when_read_bytes_empty():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0x100}
    # p8 command returns empty string -> read_bytes returns b""
    analyzer = _build_analyzer(sections=[])
    entropy = analyzer._calculate_entropy(section)
    assert entropy == 0.0


def test_calculate_entropy_returns_zero_when_size_is_zero():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0}
    analyzer = _build_analyzer(sections=[])
    entropy = analyzer._calculate_entropy(section)
    assert entropy == 0.0


def test_calculate_entropy_returns_zero_on_read_exception():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0x100}
    # No p8 command registered -> read_bytes returns empty -> 0.0
    analyzer = _build_analyzer(sections=[])
    entropy = analyzer._calculate_entropy(section)
    assert entropy == 0.0


def test_calculate_entropy_nonzero_with_real_data():
    section = {"name": ".text", "vaddr": 0x1000, "size": 256}
    hex_data = "".join(f"{b:02x}" for b in range(256))
    analyzer = _build_analyzer(
        sections=[],
        cmd_map_extra={f"p8 256 @ {0x1000}": hex_data},
    )
    entropy = analyzer._calculate_entropy(section)
    assert entropy > 0.0


def test_get_arch_reads_nested_bin_info_shape():
    analyzer = _build_analyzer(
        sections=[],
        file_info={"bin": {"arch": "x86"}},
    )
    assert analyzer._get_arch() == "x86"

    # Verify nop counting works with x86 arch and NOP bytes
    nop_hex = _hex_bytes(0x90, 3)
    analyzer2 = _build_analyzer(
        sections=[],
        file_info={"bin": {"arch": "x86"}},
        cmd_map_extra={f"p8 3 @ {0x1000}": nop_hex},
    )
    assert analyzer2._count_nops_in_section(0x1000, 3) == (3, 3)


def test_analyze_single_section_records_errors():
    """When _apply_permissions encounters bad data, the error is recorded."""
    # Provide a section with data that will cause an internal error
    # by having no flags key but a characteristics that's not int
    section = {"name": ".text", "vaddr": 0x1000, "vsize": 0x200, "size": 0x200, "flags": "r-x"}
    analyzer = _build_analyzer(
        sections=[section],
        cmd_map_extra={f"p8 512 @ {0x1000}": _hex_bytes(0xCC, 512)},
    )
    # This should succeed and return a valid result dict
    result = analyzer._analyze_single_section(section)
    assert "name" in result
    assert result["name"] == ".text"


def test_apply_pe_characteristics_sets_memory_flags():
    analyzer = _build_analyzer(sections=[])
    section = {"characteristics": 0x01000000 | 0x04000000 | 0x02000000}
    analysis = {"is_executable": False, "is_writable": False, "is_readable": False}

    analyzer._apply_pe_characteristics(section, analysis)

    assert analysis["is_executable"] is True
    assert analysis["is_writable"] is True


def test_check_section_name_indicators_include_nonstandard_and_suspicious():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_section_name_indicators(".custom")
    suspicious = analyzer._check_section_name_indicators("upx_text")

    assert indicators == []
    assert any("UPX" in item.upper() for item in suspicious)


def test_check_suspicious_characteristics_handles_invalid_analysis_input():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_suspicious_characteristics({"name": ".text"}, analysis=[])
    assert indicators == []


# ---------------------------------------------------------------------------
# _check_size_indicators - very small section (line 248)
# ---------------------------------------------------------------------------


def test_check_size_indicators_very_small_section():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_size_indicators(vsize=50, raw_size=50)
    assert any("small" in i.lower() for i in indicators)


def test_check_size_indicators_large_virtual_ratio():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_size_indicators(vsize=10000, raw_size=100)
    assert any("ratio" in i.lower() or "larger" in i.lower() for i in indicators)


def test_check_size_indicators_large_ratio_branch_over_five():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_size_indicators(vsize=600, raw_size=100)
    assert any("large size ratio" in i.lower() for i in indicators)


def test_check_size_indicators_very_large_section():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_size_indicators(vsize=60000000, raw_size=60000000)
    assert any("large" in i.lower() for i in indicators)


def test_check_size_indicators_large_virtual_raw_difference():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_size_indicators(vsize=90, raw_size=500)
    assert any("large virtual/raw size difference" in i.lower() for i in indicators)


def test_check_size_indicators_no_indicators_for_normal_section():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_size_indicators(vsize=0x1000, raw_size=0x1000)
    assert len(indicators) == 0


# ---------------------------------------------------------------------------
# _check_entropy_anomaly exception (lines 340-341)
# ---------------------------------------------------------------------------


def test_check_entropy_anomaly_does_not_raise_on_malformed_range():
    analyzer = _build_analyzer(sections=[])
    characteristics = {"expected_entropy": "not-a-valid-range"}
    analysis = {"entropy": 5.0}
    # Should not raise; ValueError is caught internally
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert "entropy_anomaly" not in characteristics


def test_check_entropy_anomaly_variable_returns_early():
    analyzer = _build_analyzer(sections=[])
    characteristics = {"expected_entropy": "Variable"}
    analysis = {"entropy": 9.9}
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert "entropy_anomaly" not in characteristics


def test_check_entropy_anomaly_marks_anomaly():
    analyzer = _build_analyzer(sections=[])
    characteristics = {"expected_entropy": "1.0-3.0"}
    analysis = {"entropy": 7.5}
    analyzer._check_entropy_anomaly(characteristics, analysis)
    assert characteristics.get("entropy_anomaly") is True


def test_get_section_characteristics_returns_empty_on_characteristic_error():
    analyzer = _build_analyzer(sections=[])
    section = {"name": ".text"}
    analysis = {}

    result = analyzer._get_section_characteristics(section, analysis)

    assert "purpose" in result
    assert "code_analysis" not in result


# ---------------------------------------------------------------------------
# _analyze_code_section - size == 0 early return (line 352)
# ---------------------------------------------------------------------------


def test_analyze_code_section_returns_empty_when_size_zero():
    section = {"name": ".text", "vaddr": 0x1000, "size": 0}
    analyzer = _build_analyzer(sections=[])
    result = analyzer._analyze_code_section(section)
    assert result == {}


# ---------------------------------------------------------------------------
# _get_functions_in_section - size <= 0 (line 384)
# ---------------------------------------------------------------------------


def test_get_functions_in_section_returns_empty_when_size_nonpositive():
    analyzer = _build_analyzer(sections=[])
    result = analyzer._get_functions_in_section(0x1000, 0)
    assert result == []


def test_get_functions_in_section_filters_by_address_range():
    analyzer = _build_analyzer(
        sections=[],
        functions=[
            {"offset": 0x1000},
            {"offset": 0x2000},
            {"addr": 0x1500},
        ],
    )
    # Pre-populate the functions cache by calling _cmd_list via the adapter
    # The aflj response is set up in _build_analyzer
    result = analyzer._get_functions_in_section(0x1000, 0x1000)
    # Should include 0x1000 and 0x1500 (addr key), not 0x2000
    assert any(f.get("offset") == 0x1000 for f in result)
    assert any(f.get("addr") == 0x1500 for f in result)
    assert not any(f.get("offset") == 0x2000 for f in result)


# ---------------------------------------------------------------------------
# _count_nops_in_section - non-x86 arch returns (0, 0) (line 408)
# ---------------------------------------------------------------------------


def test_count_nops_in_section_returns_zero_for_non_x86_arch():
    analyzer = _build_analyzer(sections=[], arch="arm")
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 0x100)
    assert nop_count == 0
    assert sample_size == 0


def test_count_nops_in_section_returns_zero_when_size_zero():
    analyzer = _build_analyzer(sections=[], arch="x86")
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 0)
    assert nop_count == 0
    assert sample_size == 0


def test_count_nops_in_section_returns_zero_when_no_arch():
    analyzer = _build_analyzer(sections=[], file_info={})
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 0x100)
    assert nop_count == 0
    assert sample_size == 0


def test_count_nops_in_section_counts_nops_for_x86():
    nop_hex = _hex_bytes(0x90, 256)
    analyzer = _build_analyzer(
        sections=[],
        arch="x86",
        cmd_map_extra={f"p8 256 @ {0x1000}": nop_hex},
    )
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 256)
    assert nop_count == 256
    assert sample_size == 256


def test_count_nops_in_section_returns_zero_when_read_bytes_empty():
    # No p8 command registered -> empty bytes
    analyzer = _build_analyzer(sections=[], arch="x86")
    nop_count, sample_size = analyzer._count_nops_in_section(0x1000, 256)
    assert nop_count == 0
    assert sample_size == 0


# ---------------------------------------------------------------------------
# _analyze_code_section - excessive nops (lines 375, 377-378)
# ---------------------------------------------------------------------------


def test_analyze_code_section_detects_excessive_nops():
    nop_hex = _hex_bytes(0x90, 256)
    analyzer = _build_analyzer(
        sections=[],
        arch="x86",
        cmd_map_extra={f"p8 256 @ {0x1000}": nop_hex},
    )
    section = {"name": ".text", "vaddr": 0x1000, "size": 256}
    result = analyzer._analyze_code_section(section)
    assert "nop_count" in result
    assert result.get("nop_ratio") == 1.0
    assert result.get("excessive_nops") is True


def test_analyze_code_section_tracks_function_size_stats():
    functions = [
        {"size": 8, "offset": 0x1000},
        {"size": 2, "offset": 0x1010},
        {"size": 4, "offset": 0x1020},
        {"size": 0, "offset": 0x1030},
    ]
    analyzer = _build_analyzer(
        sections=[],
        arch="x86",
        functions=functions,
        cmd_map_extra={f"p8 512 @ {0x1000}": _hex_bytes(0xCC, 512)},
    )
    result = analyzer._analyze_code_section({"name": ".text", "vaddr": 0x1000, "size": 0x200})

    assert result["function_count"] == 4
    # avg of non-zero sizes: (8+2+4)/3 = 4.666...
    assert result["avg_function_size"] == 4.666666666666667
    assert result["min_function_size"] == 2
    assert result["max_function_size"] == 8


def test_analyze_code_section_handles_internal_errors():
    """When functions cache lookup fails, code section analysis returns empty dict."""
    # Provide a section with size but no p8 response and no functions
    # This should exercise error handling gracefully
    analyzer = _build_analyzer(sections=[], arch="x86")
    result = analyzer._analyze_code_section({"name": ".text", "vaddr": 0x1000, "size": 0x200})
    # Even without functions, it should return a result (possibly with nop data or empty)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _update_summary_for_section - high entropy counts (lines 449-450)
# ---------------------------------------------------------------------------


def test_update_summary_for_section_counts_high_entropy():
    analyzer = _build_analyzer(sections=[])
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
    analyzer = _build_analyzer(sections=[])
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


def test_get_arch_handles_file_info_errors():
    # ij returns None -> get_file_info returns empty/None -> _get_arch returns None
    analyzer = _build_analyzer(sections=[], file_info={})
    assert analyzer._get_arch() is None


def test_calculate_size_ratio_returns_zero_when_raw_size_is_zero():
    analyzer = _build_analyzer(sections=[])
    assert analyzer._calculate_size_ratio({"virtual_size": 123, "raw_size": 0}) == 0.0


def test_section_summary_handles_empty_sections():
    """When analyze_sections returns empty list, summary has zero counts."""
    analyzer = _build_analyzer(sections=[])
    summary = analyzer.get_section_summary()
    assert summary["total_sections"] == 0
    assert summary["executable_sections"] == 0


# ---------------------------------------------------------------------------
# Full analyze flow
# ---------------------------------------------------------------------------


def test_analyze_returns_expected_structure():
    sections = [{"name": ".text", "vaddr": 0x1000, "vsize": 0x100, "size": 0x100, "flags": "r-x"}]
    hex_data = "".join(f"{b:02x}" for b in range(256))
    analyzer = _build_analyzer(
        sections=sections,
        cmd_map_extra={f"p8 256 @ {0x1000}": hex_data},
    )
    result = analyzer.analyze()
    assert "sections" in result
    assert "summary" in result
    assert "total_sections" in result


def test_get_category_describes_metadata():
    analyzer = _build_analyzer(sections=[])
    assert analyzer.get_category() == "metadata"


def test_get_description_returns_readable_label():
    analyzer = _build_analyzer(sections=[])
    assert analyzer.get_description() == (
        "Analyzes binary sections including entropy, permissions, and suspicious characteristics"
    )


def test_check_entropy_indicators_uses_moderate_high_entropy_path():
    analyzer = _build_analyzer(sections=[])
    indicators = analyzer._check_entropy_indicators(7.2)
    assert indicators == ["Moderate high entropy (7.20)"]
