#!/usr/bin/env python3
"""Unit tests for small utility modules (items 1-11)."""

import hashlib
import math
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. pe_imports
# ---------------------------------------------------------------------------
from r2inspect.modules.pe_imports import (
    compute_imphash,
    group_imports_by_library,
    normalize_library_name,
)


def test_group_imports_by_library_basic():
    imports = [
        {"name": "CreateFile", "libname": "kernel32.dll"},
        {"name": "WriteFile", "libname": "kernel32.dll"},
        {"name": "connect", "libname": "ws2_32.dll"},
    ]
    result = group_imports_by_library(imports)
    assert "kernel32.dll" in result
    assert "CreateFile" in result["kernel32.dll"]
    assert "WriteFile" in result["kernel32.dll"]
    assert "ws2_32.dll" in result
    assert "connect" in result["ws2_32.dll"]


def test_group_imports_by_library_missing_libname():
    imports = [{"name": "SomeFunc"}]
    result = group_imports_by_library(imports)
    assert "unknown" in result
    assert "SomeFunc" in result["unknown"]


def test_group_imports_by_library_empty_libname():
    imports = [{"name": "Func", "libname": "   "}]
    result = group_imports_by_library(imports)
    assert "unknown" in result


def test_group_imports_by_library_skips_nameless():
    imports = [{"libname": "kernel32.dll", "name": ""}]
    result = group_imports_by_library(imports)
    assert result == {}


def test_group_imports_by_library_skips_non_dict():
    imports = ["not_a_dict", {"name": "Func", "libname": "lib.dll"}]
    result = group_imports_by_library(imports)
    assert "lib.dll" in result


def test_normalize_library_name_removes_dll():
    result = normalize_library_name("KERNEL32.DLL", ["dll", "sys", "ocx"])
    assert result == "kernel32"


def test_normalize_library_name_removes_sys():
    result = normalize_library_name("ntdll.sys", ["dll", "sys", "ocx"])
    assert result == "ntdll"


def test_normalize_library_name_keeps_unknown_ext():
    result = normalize_library_name("mylib.xyz", ["dll", "sys", "ocx"])
    assert result == "mylib.xyz"


def test_normalize_library_name_bytes_input():
    result = normalize_library_name(b"KERNEL32.DLL", ["dll"])
    assert result == "kernel32"


def test_compute_imphash_empty():
    assert compute_imphash([]) == ""


def test_compute_imphash_basic():
    strings = ["kernel32.createfile", "ws2_32.connect"]
    expected = hashlib.md5(
        ",".join(strings).encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    assert compute_imphash(strings) == expected


# ---------------------------------------------------------------------------
# 2. simhash_detailed – test only the unavailable-library branch (no simhash dep)
# ---------------------------------------------------------------------------
from r2inspect.modules.simhash_detailed import run_detailed_simhash_analysis


def test_run_detailed_simhash_unavailable():
    result = run_detailed_simhash_analysis(
        filepath="test.bin",
        simhash_available=False,
        no_features_error="no features",
        extract_string_features=lambda: [],
        extract_opcodes_features=lambda: [],
        extract_function_features=lambda: {},
        find_similar_functions=lambda x: [],
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert result["available"] is False
    assert result["library_available"] is False


# ---------------------------------------------------------------------------
# 3. hashing_strategy
# ---------------------------------------------------------------------------
from r2inspect.abstractions.hashing_strategy import HashingStrategy, R2HashingStrategy


class _ConcreteHasher(HashingStrategy):
    """Minimal concrete implementation for testing the abstract base."""

    def _check_library_availability(self):
        return True, None

    def _calculate_hash(self):
        return "deadbeef", "test_method", None

    def _get_hash_type(self):
        return "test"

    @staticmethod
    def compare_hashes(h1, h2):
        return 0

    @staticmethod
    def is_available():
        return True


def test_hashing_strategy_raises_empty_filepath():
    try:
        _ConcreteHasher("")
        assert False, "should have raised"
    except ValueError as exc:
        assert "empty" in str(exc).lower()


def test_hashing_strategy_raises_negative_max():
    try:
        _ConcreteHasher("/tmp/x", max_file_size=-1)
        assert False, "should have raised"
    except ValueError:
        pass


def test_hashing_strategy_raises_min_exceeds_max():
    try:
        _ConcreteHasher("/tmp/x", min_file_size=200, max_file_size=100)
        assert False, "should have raised"
    except ValueError:
        pass


def test_hashing_strategy_validate_file_nonexistent(tmp_path):
    hasher = _ConcreteHasher(str(tmp_path / "nonexistent.bin"))
    err = hasher._validate_file()
    assert err is not None
    assert "does not exist" in err


def test_hashing_strategy_validate_file_directory(tmp_path):
    hasher = _ConcreteHasher(str(tmp_path))
    err = hasher._validate_file()
    assert err is not None
    assert "not a regular file" in err


def test_hashing_strategy_validate_file_too_small(tmp_path):
    f = tmp_path / "tiny.bin"
    f.write_bytes(b"")
    hasher = _ConcreteHasher(str(f), min_file_size=10)
    err = hasher._validate_file()
    assert err is not None
    assert "too small" in err


def test_hashing_strategy_validate_file_too_large(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 10)
    hasher = _ConcreteHasher(str(f), max_file_size=5)
    err = hasher._validate_file()
    assert err is not None
    assert "too large" in err


def test_hashing_strategy_validate_file_ok(tmp_path):
    f = tmp_path / "ok.bin"
    f.write_bytes(b"hello world")
    hasher = _ConcreteHasher(str(f))
    err = hasher._validate_file()
    assert err is None


def test_hashing_strategy_get_file_size(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"abcde")
    hasher = _ConcreteHasher(str(f))
    assert hasher.get_file_size() == 5


def test_hashing_strategy_get_file_size_missing(tmp_path):
    hasher = _ConcreteHasher(str(tmp_path / "missing.bin"))
    assert hasher.get_file_size() is None


def test_hashing_strategy_get_file_extension(tmp_path):
    f = tmp_path / "sample.EXE"
    f.write_bytes(b"x")
    hasher = _ConcreteHasher(str(f))
    assert hasher.get_file_extension() == "exe"


def test_hashing_strategy_str_repr(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    hasher = _ConcreteHasher(str(f))
    assert "test" in str(hasher)
    assert "x.bin" in str(hasher)
    assert "ConcreteHasher" in repr(hasher)


def test_hashing_strategy_analyze_missing_file(tmp_path):
    hasher = _ConcreteHasher(str(tmp_path / "ghost.bin"))
    result = hasher.analyze()
    assert result["available"] is False
    assert result["error"] is not None


def test_hashing_strategy_analyze_ok(tmp_path):
    f = tmp_path / "ok.bin"
    f.write_bytes(b"hello")
    hasher = _ConcreteHasher(str(f))
    result = hasher.analyze()
    assert result["available"] is True
    assert result["hash_value"] == "deadbeef"
    assert result["method_used"] == "test_method"


def test_r2_hashing_strategy_basic(tmp_path):
    f = tmp_path / "ok.bin"
    f.write_bytes(b"hello")

    class _StubAdapter:
        pass

    class _ConcreteR2Hasher(R2HashingStrategy):
        def _check_library_availability(self):
            return True, None

        def _calculate_hash(self):
            return "abc", "method", None

        def _get_hash_type(self):
            return "test"

        @staticmethod
        def compare_hashes(h1, h2):
            return 0

        @staticmethod
        def is_available():
            return True

    rhs = _ConcreteR2Hasher(_StubAdapter(), str(f))
    assert rhs.adapter is not None
    assert rhs.filepath == Path(str(f))


# ---------------------------------------------------------------------------
# 4. function_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.function_domain import (
    extract_mnemonics_from_ops,
    extract_mnemonics_from_text,
    machoc_hash_from_mnemonics,
)


def test_extract_mnemonics_from_ops_basic():
    ops = [{"opcode": "mov eax, 1"}, {"opcode": "push ebp"}, {"opcode": "ret"}]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push", "ret"]


def test_extract_mnemonics_from_ops_empty_opcode_skipped():
    ops = [{"opcode": ""}, {"opcode": "   "}, {"opcode": "nop"}]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["nop"]


def test_extract_mnemonics_from_ops_missing_opcode_key():
    ops = [{"type": "reg"}, {"opcode": "xor eax, eax"}]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["xor"]


def test_extract_mnemonics_from_text_basic():
    text = "mov eax, 1\npush ebp\nret"
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push", "ret"]


def test_extract_mnemonics_from_text_empty():
    assert extract_mnemonics_from_text("") == []
    assert extract_mnemonics_from_text("   ") == []


def test_machoc_hash_from_mnemonics_none_on_empty():
    assert machoc_hash_from_mnemonics([]) is None


def test_machoc_hash_from_mnemonics_deterministic():
    mnemonics = ["mov", "push", "ret"]
    h1 = machoc_hash_from_mnemonics(mnemonics)
    h2 = machoc_hash_from_mnemonics(mnemonics)
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex length


def test_machoc_hash_differs_for_different_mnemonics():
    h1 = machoc_hash_from_mnemonics(["mov", "ret"])
    h2 = machoc_hash_from_mnemonics(["push", "pop"])
    assert h1 != h2


# ---------------------------------------------------------------------------
# 5. similarity_scoring
# ---------------------------------------------------------------------------
from r2inspect.modules.similarity_scoring import (
    jaccard_similarity,
    normalized_difference_similarity,
)


def test_jaccard_both_empty():
    assert jaccard_similarity(set(), set()) == 1.0


def test_jaccard_one_empty():
    assert jaccard_similarity({1, 2}, set()) == 0.0
    assert jaccard_similarity(set(), {1, 2}) == 0.0


def test_jaccard_identical():
    s = {1, 2, 3}
    assert jaccard_similarity(s, s) == 1.0


def test_jaccard_disjoint():
    assert jaccard_similarity({1, 2}, {3, 4}) == 0.0


def test_jaccard_partial():
    score = jaccard_similarity({1, 2, 3}, {2, 3, 4})
    assert abs(score - 0.5) < 1e-9


def test_normalized_diff_both_zero():
    assert normalized_difference_similarity(0, 0) == 0.0


def test_normalized_diff_equal():
    assert normalized_difference_similarity(100, 100) == 1.0


def test_normalized_diff_partial():
    score = normalized_difference_similarity(50, 100)
    assert abs(score - 0.5) < 1e-9


def test_normalized_diff_negative():
    assert normalized_difference_similarity(-1, 10) == 0.0


# ---------------------------------------------------------------------------
# 7. security_scoring
# ---------------------------------------------------------------------------
from r2inspect.modules.security_scoring import _grade_from_percentage, build_security_score


def _make_result(mitigations=None, vulnerabilities=None):
    return {
        "mitigations": mitigations or {},
        "vulnerabilities": vulnerabilities or [],
    }


def test_build_security_score_no_mitigations():
    result = _make_result()
    score = build_security_score(result)
    assert score["score"] == 0
    # max_score > 0 since MITIGATION_SCORES defines points; 0% → "F"
    assert score["grade"] == "F"


def test_build_security_score_all_enabled():
    mitigations = {
        "ASLR": {"enabled": True, "high_entropy": True},
        "DEP": {"enabled": True},
        "CFG": {"enabled": True},
        "RFG": {"enabled": True},
        "SafeSEH": {"enabled": True},
        "Stack_Cookies": {"enabled": True},
        "Authenticode": {"enabled": True},
        "Force_Integrity": {"enabled": True},
        "AppContainer": {"enabled": True},
    }
    result = _make_result(mitigations=mitigations)
    score = build_security_score(result)
    assert score["score"] == score["max_score"]
    assert score["percentage"] == 100.0
    assert score["grade"] == "A"


def test_build_security_score_high_vuln_penalty():
    mitigations = {"ASLR": {"enabled": True}}
    vulnerabilities = [{"severity": "high"}, {"severity": "high"}]
    result = _make_result(mitigations=mitigations, vulnerabilities=vulnerabilities)
    score = build_security_score(result)
    # Penalties can drive score below threshold but clamp keeps it ≥ 0
    assert score["score"] >= 0


def test_grade_from_percentage_unknown():
    assert _grade_from_percentage(95.0, 0) == "Unknown"


def test_grade_from_percentage_a():
    assert _grade_from_percentage(90.0, 100) == "A"
    assert _grade_from_percentage(100.0, 100) == "A"


def test_grade_from_percentage_b():
    assert _grade_from_percentage(85.0, 100) == "B"


def test_grade_from_percentage_c():
    assert _grade_from_percentage(75.0, 100) == "C"


def test_grade_from_percentage_d():
    assert _grade_from_percentage(65.0, 100) == "D"


def test_grade_from_percentage_f():
    assert _grade_from_percentage(50.0, 100) == "F"


# ---------------------------------------------------------------------------
# 8. string_extraction
# ---------------------------------------------------------------------------
from r2inspect.modules.string_extraction import (
    extract_ascii_from_bytes,
    extract_strings_from_entries,
    split_null_terminated,
)


def test_extract_strings_from_entries_basic():
    entries = [{"string": "hello"}, {"string": "world"}, {"string": "hi"}]
    result = extract_strings_from_entries(entries, min_length=4)
    assert "hello" in result
    assert "world" in result
    assert "hi" not in result  # too short


def test_extract_strings_from_entries_none():
    assert extract_strings_from_entries(None, min_length=4) == []


def test_extract_strings_from_entries_empty():
    assert extract_strings_from_entries([], min_length=4) == []


def test_extract_strings_from_entries_missing_string_key():
    entries = [{"value": "no_string_key"}]
    result = extract_strings_from_entries(entries, min_length=4)
    assert result == []


def test_extract_ascii_from_bytes_basic():
    data = list(b"hello\x00world")
    result = extract_ascii_from_bytes(data, min_length=4)
    assert "hello" in result
    assert "world" in result


def test_extract_ascii_from_bytes_too_short():
    data = list(b"hi\x00there")
    result = extract_ascii_from_bytes(data, min_length=4)
    assert "hi" not in result
    assert "there" in result


def test_extract_ascii_from_bytes_limit():
    # Build many separated strings
    data = []
    for _ in range(100):
        data.extend(list(b"test"))
        data.append(0x00)
    result = extract_ascii_from_bytes(data, min_length=4, limit=10)
    assert len(result) <= 10


def test_split_null_terminated_basic():
    result = split_null_terminated("hello\x00world\x00hi", min_length=4)
    assert "hello" in result
    assert "world" in result
    assert "hi" not in result


def test_split_null_terminated_empty():
    assert split_null_terminated("", min_length=4) == []


def test_split_null_terminated_limit():
    text = "\x00".join(["abcde"] * 100)
    result = split_null_terminated(text, min_length=4, limit=5)
    assert len(result) <= 5


# ---------------------------------------------------------------------------
# 9. crypto_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.crypto_domain import (
    consolidate_detections,
    detect_algorithms_from_strings,
)


def test_detect_algorithms_from_strings_aes():
    strings = [{"string": "aes_cbc_encrypt", "vaddr": 0x1000}]
    detected: dict = {}
    detect_algorithms_from_strings(strings, detected)
    assert "AES" in detected


def test_detect_algorithms_from_strings_md5():
    strings = [{"string": "md5 hash computed", "vaddr": 0x2000}]
    detected: dict = {}
    detect_algorithms_from_strings(strings, detected)
    assert "MD5" in detected


def test_detect_algorithms_from_strings_noise_skipped():
    strings = [{"string": "std::string", "vaddr": 0}]
    detected: dict = {}
    detect_algorithms_from_strings(strings, detected)
    assert detected == {}


def test_detect_algorithms_from_strings_short_string_skipped():
    strings = [{"string": "ab", "vaddr": 0}]
    detected: dict = {}
    detect_algorithms_from_strings(strings, detected)
    assert detected == {}


def test_consolidate_detections_single_type():
    detected = {
        "AES": [
            {"evidence_type": "String Reference", "evidence": "aes", "confidence": 0.4, "address": "0x0"}
        ]
    }
    result = consolidate_detections(detected)
    assert len(result) == 1
    assert result[0]["algorithm"] == "AES"
    assert result[0]["confidence"] == 0.4


def test_consolidate_detections_multiple_types_boost():
    detected = {
        "RSA": [
            {"evidence_type": "String Reference", "evidence": "rsa", "confidence": 0.4, "address": "0x0"},
            {"evidence_type": "Import Reference", "evidence": "rsa_key", "confidence": 0.6, "address": "0x1"},
        ]
    }
    result = consolidate_detections(detected)
    assert result[0]["confidence"] > 0.6  # boosted because 2 types


def test_consolidate_detections_empty():
    assert consolidate_detections({}) == []


# ---------------------------------------------------------------------------
# 10. anti_analysis_helpers
# ---------------------------------------------------------------------------
from r2inspect.modules.anti_analysis_helpers import (
    add_simple_evidence,
    collect_artifact_strings,
    count_opcode_occurrences,
    detect_api_hashing,
    detect_environment_checks,
    detect_injection_apis,
    detect_obfuscation,
    detect_self_modifying,
    match_suspicious_api,
)


def test_collect_artifact_strings_basic():
    strings = [
        {"string": "VirtualBox", "vaddr": 0x1000},
        {"string": "normal string", "vaddr": 0x2000},
    ]
    result = collect_artifact_strings(strings, ["VirtualBox", "VMware"])
    assert len(result) == 1
    assert result[0]["artifact"] == "VirtualBox"


def test_collect_artifact_strings_case_insensitive():
    strings = [{"string": "VMWARE TOOLS", "vaddr": 0}]
    result = collect_artifact_strings(strings, ["vmware"])
    assert len(result) == 1


def test_collect_artifact_strings_none_input():
    assert collect_artifact_strings(None, ["vm"]) == []


def test_collect_artifact_strings_empty_strings():
    assert collect_artifact_strings([], ["vm"]) == []


def test_add_simple_evidence_basic():
    result = {"detected": False, "evidence": []}
    add_simple_evidence(
        result,
        checks="0x1000\n0x2000",
        evidence_type="OpcodePattern",
        detail_prefix="test detail",
        field="addresses",
        limit=10,
    )
    assert result["detected"] is True
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["type"] == "OpcodePattern"


def test_add_simple_evidence_empty_checks():
    result = {"detected": False, "evidence": []}
    add_simple_evidence(result, checks="", evidence_type="T", detail_prefix="d", field="x", limit=5)
    assert result["detected"] is False


def test_count_opcode_occurrences_basic():
    def search(pattern):
        return "match1\nmatch2\nmatch3"

    assert count_opcode_occurrences(search, "jmp") == 3


def test_count_opcode_occurrences_no_match():
    def search(pattern):
        return ""

    assert count_opcode_occurrences(search, "jmp") == 0


def test_detect_obfuscation_high_jumps():
    def search(pattern):
        if pattern == "jmp":
            return "\n".join(["x"] * 150)
        return "\n".join(["x"] * 250)

    result = detect_obfuscation(search)
    assert len(result) == 1
    assert result[0]["technique"] == "Code Obfuscation"


def test_detect_obfuscation_low_count():
    def search(pattern):
        return "one"

    result = detect_obfuscation(search)
    assert result == []


def test_detect_self_modifying_detected():
    def cmd(pattern):
        return "mov eax, cs:0x1000"

    result = detect_self_modifying(cmd)
    assert len(result) == 1
    assert result[0]["severity"] == "High"


def test_detect_self_modifying_none():
    def cmd(pattern):
        return ""

    assert detect_self_modifying(cmd) == []


def test_detect_api_hashing_detected():
    def cmd(pattern):
        return "crc32 hash found"

    result = detect_api_hashing(cmd)
    assert len(result) == 1
    assert result[0]["technique"] == "API Hashing"


def test_detect_api_hashing_none():
    def cmd(pattern):
        return ""

    assert detect_api_hashing(cmd) == []


def test_detect_injection_apis_threshold():
    imports = [
        {"name": "VirtualAllocEx"},
        {"name": "WriteProcessMemory"},
        {"name": "CreateRemoteThread"},
    ]
    apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    result = detect_injection_apis(imports, apis)
    assert len(result) == 1
    assert result[0]["severity"] == "High"


def test_detect_injection_apis_below_threshold():
    imports = [{"name": "VirtualAllocEx"}]
    apis = {"VirtualAllocEx", "WriteProcessMemory"}
    result = detect_injection_apis(imports, apis)
    assert result == []


def test_detect_injection_apis_none_imports():
    assert detect_injection_apis(None, {"VirtualAllocEx"}) == []


def test_match_suspicious_api_found():
    imp = {"name": "CreateRemoteThread", "plt": 0x4000}
    categories = {"injection": ["CreateRemoteThread"]}
    result = match_suspicious_api(imp, categories)
    assert result is not None
    assert result["category"] == "injection"


def test_match_suspicious_api_not_found():
    imp = {"name": "printf", "plt": 0}
    categories = {"injection": ["CreateRemoteThread"]}
    assert match_suspicious_api(imp, categories) is None


def test_detect_environment_checks_basic():
    def cmd(command):
        return "some output"

    env_commands = [
        ("iz~cpuid", "cpuid", "CPUID check"),
        ("iz~rdtsc", "rdtsc", "RDTSC check"),
    ]
    result = detect_environment_checks(cmd, env_commands)
    assert len(result) == 2


def test_detect_environment_checks_empty_output():
    def cmd(command):
        return ""

    env_commands = [("iz~cpuid", "cpuid", "CPUID")]
    result = detect_environment_checks(cmd, env_commands)
    assert result == []


# ---------------------------------------------------------------------------
# 11. domain_helpers
# ---------------------------------------------------------------------------
from r2inspect.modules.domain_helpers import (
    clamp_score,
    count_suspicious_imports,
    entropy_from_ints,
    normalize_section_name,
    shannon_entropy,
    suspicious_section_name_indicator,
)


def test_shannon_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_uniform():
    data = bytes(range(256))
    assert abs(shannon_entropy(data) - 8.0) < 1e-9


def test_shannon_entropy_all_same():
    assert shannon_entropy(b"\x00" * 100) == 0.0


def test_shannon_entropy_two_values():
    data = b"\x00\xFF" * 50
    assert abs(shannon_entropy(data) - 1.0) < 1e-9


def test_entropy_from_ints_empty():
    assert entropy_from_ints([]) == 0.0


def test_entropy_from_ints_uniform():
    data = list(range(256))
    assert abs(entropy_from_ints(data) - 8.0) < 1e-9


def test_clamp_score_within():
    assert clamp_score(50) == 50


def test_clamp_score_below():
    assert clamp_score(-5) == 0


def test_clamp_score_above():
    assert clamp_score(150) == 100


def test_clamp_score_custom_bounds():
    assert clamp_score(5, minimum=10, maximum=20) == 10
    assert clamp_score(25, minimum=10, maximum=20) == 20


def test_count_suspicious_imports_basic():
    imports = [{"name": "VirtualAlloc"}, {"name": "CreateThread"}, {"name": "printf"}]
    suspicious = {"VirtualAlloc", "CreateThread"}
    assert count_suspicious_imports(imports, suspicious) == 2


def test_count_suspicious_imports_empty():
    assert count_suspicious_imports([], {"VirtualAlloc"}) == 0


def test_normalize_section_name_lowercase():
    assert normalize_section_name(".TEXT") == ".text"


def test_normalize_section_name_none():
    assert normalize_section_name(None) == ""


def test_suspicious_section_name_indicator_found():
    result = suspicious_section_name_indicator(".malware", [".malware", ".upx"])
    assert result is not None
    assert ".malware" in result


def test_suspicious_section_name_indicator_not_found():
    assert suspicious_section_name_indicator(".text", [".upx", ".vmp"]) is None
