#!/usr/bin/env python3
"""Branch path tests for miscellaneous module helpers."""

from __future__ import annotations

import pytest

from r2inspect.modules.domain_helpers import (
    clamp_score,
    count_suspicious_imports,
    entropy_from_ints,
    normalize_section_name,
    shannon_entropy,
)
from r2inspect.modules.packer_helpers import (
    analyze_sections,
    calculate_section_entropy,
)
from r2inspect.modules.anti_analysis_helpers import (
    add_simple_evidence,
    count_opcode_occurrences,
    detect_api_hashing,
    detect_environment_checks,
    detect_obfuscation,
    detect_self_modifying,
)
from r2inspect.modules.exploit_mitigation_rules import generate_recommendations
from r2inspect.modules.pe_analyzer import PEAnalyzer
from r2inspect.modules.search_helpers import search_hex, search_text
from r2inspect.modules.string_classification import classify_string_type


# ---------------------------------------------------------------------------
# domain_helpers.py
# ---------------------------------------------------------------------------

def test_shannon_entropy_empty_bytes_returns_zero() -> None:
    """shannon_entropy returns 0.0 for empty bytes."""
    assert shannon_entropy(b"") == 0.0


def test_entropy_from_ints_empty_list_returns_zero() -> None:
    """entropy_from_ints returns 0.0 for empty list."""
    assert entropy_from_ints([]) == 0.0


def test_clamp_score_below_minimum_returns_minimum() -> None:
    """clamp_score returns minimum when score is below minimum."""
    assert clamp_score(-5) == 0


def test_clamp_score_above_maximum_returns_maximum() -> None:
    """clamp_score returns maximum when score exceeds maximum."""
    assert clamp_score(200) == 100


def test_count_suspicious_imports_returns_count() -> None:
    """count_suspicious_imports counts imports whose name is in suspicious set."""
    imports = [{"name": "VirtualAlloc"}, {"name": "CreateFile"}, {"name": "malloc"}]
    suspicious = {"VirtualAlloc", "CreateFile"}
    assert count_suspicious_imports(imports, suspicious) == 2


def test_normalize_section_name_returns_lowercase_for_string() -> None:
    """normalize_section_name lowercases a string name."""
    assert normalize_section_name(".TEXT") == ".text"


def test_normalize_section_name_returns_empty_for_none() -> None:
    """normalize_section_name returns empty string for None."""
    assert normalize_section_name(None) == ""


# ---------------------------------------------------------------------------
# packer_helpers.py
# ---------------------------------------------------------------------------

def test_calculate_section_entropy_returns_zero_for_zero_size() -> None:
    """calculate_section_entropy returns 0.0 when section size is 0."""
    def never_called(addr, size):
        raise AssertionError("should not be called")

    result = calculate_section_entropy(never_called, {"vaddr": 0, "size": 0})
    assert result == 0.0


def test_calculate_section_entropy_returns_zero_on_exception() -> None:
    """calculate_section_entropy returns 0.0 when read_bytes_fn raises."""
    def failing_reader(addr, size):
        raise OSError("read error")

    result = calculate_section_entropy(failing_reader, {"vaddr": 0x1000, "size": 512})
    assert result == 0.0


def test_calculate_section_entropy_too_large_size_returns_zero() -> None:
    """calculate_section_entropy returns 0.0 when section size exceeds 10MB."""
    def never_called(addr, size):
        raise AssertionError("should not be called")

    result = calculate_section_entropy(never_called, {"vaddr": 0, "size": 20_000_000})
    assert result == 0.0


# ---------------------------------------------------------------------------
# anti_analysis_helpers.py
# ---------------------------------------------------------------------------

def test_detect_obfuscation_triggers_with_high_jump_count() -> None:
    """detect_obfuscation detects code obfuscation when jmp count is high."""
    jmp_lines = "\n".join(f"0x{i:08x}: jmp 0x0" for i in range(150))
    call_lines = "\n".join(f"0x{i:08x}: call 0x0" for i in range(10))

    def search_fn(pattern):
        if "jmp" in pattern:
            return jmp_lines
        return call_lines

    result = detect_obfuscation(search_fn)
    assert len(result) == 1
    assert result[0]["technique"] == "Code Obfuscation"


def test_detect_self_modifying_triggers_with_cs_modification() -> None:
    """detect_self_modifying returns technique when code segment modification found."""
    def cmd_fn(pattern):
        return "0x1000: mov cs:something"

    result = detect_self_modifying(cmd_fn)
    assert len(result) == 1
    assert result[0]["technique"] == "Self-Modifying Code"


def test_detect_api_hashing_triggers_with_hash_string() -> None:
    """detect_api_hashing returns technique when hash patterns found."""
    def cmd_fn(pattern):
        return "0x2000: hash_function"

    result = detect_api_hashing(cmd_fn)
    assert len(result) == 1
    assert result[0]["technique"] == "API Hashing"


def test_detect_environment_checks_adds_check_on_output() -> None:
    """detect_environment_checks appends a check when command output is non-empty."""
    def cmd_fn(command):
        return "0x3000: cpuid"

    commands = [("iz~cpuid", "Anti-VM", "CPUID instruction detected")]
    result = detect_environment_checks(cmd_fn, commands)
    assert len(result) == 1
    assert result[0]["type"] == "Anti-VM"


# ---------------------------------------------------------------------------
# exploit_mitigation_rules.py
# ---------------------------------------------------------------------------

def test_generate_recommendations_aslr_enabled_no_high_entropy_adds_rec() -> None:
    """generate_recommendations adds high entropy ASLR rec when ASLR on but no high entropy."""
    result = {
        "mitigations": {
            "ASLR": {"enabled": True, "high_entropy": False},
            "DEP": {"enabled": True},
            "CFG": {"enabled": True},
            "Integrity": {"enabled": True},
            "StackCookies": {"enabled": True},
            "SafeSEH": {"enabled": True},
            "Authenticode": {"enabled": True},
        },
        "pe_info": {"is_64bit": True},
    }
    recs = generate_recommendations(result)
    assert any(r["mitigation"] == "High Entropy ASLR" for r in recs)


def test_generate_recommendations_32bit_no_safe_seh_adds_rec() -> None:
    """generate_recommendations adds SafeSEH recommendation for 32-bit binaries."""
    result = {
        "mitigations": {
            "ASLR": {"enabled": True, "high_entropy": True},
            "DEP": {"enabled": True},
            "CFG": {"enabled": True},
            "Integrity": {"enabled": True},
            "StackCookies": {"enabled": True},
            "SafeSEH": {"enabled": False},
            "Authenticode": {"enabled": True},
        },
        "pe_info": {"is_64bit": False},
    }
    recs = generate_recommendations(result)
    assert any(r["mitigation"] == "SafeSEH" for r in recs)


# ---------------------------------------------------------------------------
# pe_analyzer.py
# ---------------------------------------------------------------------------

def test_pe_analyzer_supports_format_returns_true_for_pe() -> None:
    """PEAnalyzer.supports_format returns True for PE format."""
    analyzer = PEAnalyzer(adapter=None)
    assert analyzer.supports_format("PE") is True


def test_pe_analyzer_supports_format_returns_false_for_elf() -> None:
    """PEAnalyzer.supports_format returns False for ELF format."""
    analyzer = PEAnalyzer(adapter=None)
    assert analyzer.supports_format("ELF") is False


def test_pe_analyzer_determine_pe_format_delegates() -> None:
    """PEAnalyzer._determine_pe_format delegates to domain helper."""
    analyzer = PEAnalyzer(adapter=None)
    bin_info = {"class": "PE32"}
    result = analyzer._determine_pe_format(bin_info, None)
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# search_helpers.py
# ---------------------------------------------------------------------------

def test_search_text_returns_empty_string_when_adapter_is_none() -> None:
    """search_text returns empty string when adapter is None."""
    result = search_text(None, None, "pattern")
    assert result == ""


def test_search_hex_returns_empty_string_when_adapter_is_none() -> None:
    """search_hex returns empty string when adapter is None."""
    result = search_hex(None, None, "deadbeef")
    assert result == ""


class _AdapterWithSearch:
    def search_text(self, pattern: str) -> str:
        return f"found:{pattern}"

    def search_hex(self, pattern: str) -> str:
        return f"hex:{pattern}"


def test_search_text_delegates_to_adapter() -> None:
    """search_text calls adapter.search_text when adapter has the method."""
    adapter = _AdapterWithSearch()
    result = search_text(adapter, None, "test")
    assert result == "found:test"


def test_search_hex_delegates_to_adapter() -> None:
    """search_hex calls adapter.search_hex when adapter has the method."""
    adapter = _AdapterWithSearch()
    result = search_hex(adapter, None, "deadbeef")
    assert result == "hex:deadbeef"


# ---------------------------------------------------------------------------
# string_classification.py
# ---------------------------------------------------------------------------

def test_classify_string_type_url_pattern() -> None:
    """classify_string_type returns 'url' for http:// strings."""
    result = classify_string_type("http://malicious.example.com/payload")
    assert result == "url"


def test_classify_string_type_registry_pattern() -> None:
    """classify_string_type returns 'registry' for HKEY_ strings."""
    result = classify_string_type("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft")
    assert result == "registry"


def test_classify_string_type_returns_none_for_plain_string() -> None:
    """classify_string_type returns None for unclassifiable strings."""
    result = classify_string_type("hello world")
    assert result is None


# ---------------------------------------------------------------------------
# pe_resources.py - exception paths
# ---------------------------------------------------------------------------

def test_get_resource_info_returns_empty_list_on_exception() -> None:
    """get_resource_info returns empty list when adapter raises an exception."""
    from r2inspect.modules.pe_resources import get_resource_info
    from r2inspect.utils.logger import get_logger

    class BrokenAdapter:
        def get_resources_info(self):
            raise RuntimeError("broken")

    logger = get_logger("test")
    result = get_resource_info(BrokenAdapter(), logger)
    assert result == []


def test_get_resource_info_returns_data_when_adapter_works() -> None:
    """get_resource_info extends resources when adapter returns resource data."""
    from r2inspect.modules.pe_resources import get_resource_info
    from r2inspect.utils.logger import get_logger

    class GoodAdapter:
        def get_resources_info(self):
            return [{"name": "ICON", "type": 3, "vaddr": 0x1000, "size": 100}]

    logger = get_logger("test")
    result = get_resource_info(GoodAdapter(), logger)
    assert isinstance(result, list)


def test_get_version_info_returns_empty_dict_on_exception() -> None:
    """get_version_info returns empty dict when adapter raises an exception."""
    from r2inspect.modules.pe_resources import get_version_info
    from r2inspect.utils.logger import get_logger

    class BrokenAdapter:
        def get_pe_version_info_text(self):
            raise RuntimeError("broken")

    logger = get_logger("test")
    result = get_version_info(BrokenAdapter(), logger)
    assert result == {}


def test_get_version_info_returns_data_when_adapter_works() -> None:
    """get_version_info parses version info when adapter returns text."""
    from r2inspect.modules.pe_resources import get_version_info
    from r2inspect.utils.logger import get_logger

    class GoodAdapter:
        def get_pe_version_info_text(self):
            return "FileVersion: 1.0.0.0\nProductVersion: 1.0.0.0\n"

    logger = get_logger("test")
    result = get_version_info(GoodAdapter(), logger)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# authenticode_analyzer.py - exception paths
# ---------------------------------------------------------------------------

def test_extract_cn_entry_returns_none_for_out_of_bounds() -> None:
    """_extract_cn_entry returns None when pos+10 >= len(pkcs7_data)."""
    from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer

    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0] * 5
    result = analyzer._extract_cn_entry(data, 0, 0)
    assert result is None


def test_extract_cn_entry_exception_in_bytes_conversion() -> None:
    """_extract_cn_entry covers exception handler when bytes() value is out of range."""
    from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer

    analyzer = AuthenticodeAnalyzer(adapter=None)
    # Craft data: length=3, but one byte value > 255 triggers ValueError in bytes()
    data = [0, 0, 0, 0, 3, 65, 300, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    result = analyzer._extract_cn_entry(data, 0, 0)
    assert result is None


def test_verify_signature_integrity_exception_path_returns_false() -> None:
    """_verify_signature_integrity returns False when signature_info.get raises."""
    from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer

    class ExplodingInfo:
        def get(self, key, default=None):
            raise RuntimeError("Simulated error")

    analyzer = AuthenticodeAnalyzer(adapter=None)
    result = analyzer._verify_signature_integrity(ExplodingInfo())
    assert result is False
