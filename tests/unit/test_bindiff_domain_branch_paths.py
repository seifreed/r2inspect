"""Branch-path coverage tests for r2inspect/modules/bindiff_domain.py.

Targets lines:
  68-73   calculate_cyclomatic_complexity
  85-91   compare_rolling_hashes
  95-103  categorize_similarity
  168-211 compare_structural_features / compare_function_features
  215-239 compare_string_features
  243-253 compare_byte_features
  257-277 compare_behavioral_features
  287-304 calculate_overall_similarity
"""

from r2inspect.modules.bindiff_domain import (
    calculate_cyclomatic_complexity,
    calculate_overall_similarity,
    calculate_rolling_hash,
    categorize_similarity,
    compare_behavioral_features,
    compare_byte_features,
    compare_function_features,
    compare_rolling_hashes,
    compare_string_features,
    compare_structural_features,
)


# ---------------------------------------------------------------------------
# calculate_cyclomatic_complexity  (lines 68-73)
# ---------------------------------------------------------------------------


def test_cyclomatic_complexity_edges_exceed_nodes():
    cfg = {
        "edges": [{"s": 0, "d": 1}, {"s": 1, "d": 2}, {"s": 1, "d": 3}],
        "blocks": [0, 1, 2, 3],
    }
    # 3 - 4 + 2 = 1
    assert calculate_cyclomatic_complexity(cfg) == 1


def test_cyclomatic_complexity_single_node_no_edges():
    cfg = {"edges": [], "blocks": [0]}
    # 0 - 1 + 2 = 1
    assert calculate_cyclomatic_complexity(cfg) == 1


def test_cyclomatic_complexity_zero_blocks_returns_zero():
    assert calculate_cyclomatic_complexity({"edges": [1, 2], "blocks": []}) == 0


def test_cyclomatic_complexity_type_error_returns_zero():
    assert calculate_cyclomatic_complexity(42) == 0  # type: ignore[arg-type]


def test_cyclomatic_complexity_none_returns_zero():
    assert calculate_cyclomatic_complexity(None) == 0  # type: ignore[arg-type]


def test_cyclomatic_complexity_nested_list_edges():
    cfg = {"edges": [{}, {}], "blocks": [1, 2, 3]}
    # 2 - 3 + 2 = 1
    assert calculate_cyclomatic_complexity(cfg) == 1


# ---------------------------------------------------------------------------
# compare_rolling_hashes  (lines 85-91)
# ---------------------------------------------------------------------------


def test_compare_rolling_hashes_empty_first_returns_zero():
    assert compare_rolling_hashes([], [1, 2, 3]) == 0.0


def test_compare_rolling_hashes_empty_second_returns_zero():
    assert compare_rolling_hashes([1, 2, 3], []) == 0.0


def test_compare_rolling_hashes_both_empty_returns_zero():
    assert compare_rolling_hashes([], []) == 0.0


def test_compare_rolling_hashes_identical_sets_returns_one():
    h = calculate_rolling_hash(b"X" * 200, window_size=64)
    result = compare_rolling_hashes(h, h)
    assert result == 1.0


def test_compare_rolling_hashes_disjoint_returns_zero():
    result = compare_rolling_hashes([10, 20, 30], [40, 50, 60])
    assert result == 0.0


def test_compare_rolling_hashes_partial_overlap():
    result = compare_rolling_hashes([1, 2, 3], [2, 3, 4])
    # intersection = {2,3}, union = {1,2,3,4} -> 0.5
    assert 0.0 < result < 1.0


def test_compare_rolling_hashes_union_nonzero():
    result = compare_rolling_hashes([7], [7])
    assert result == 1.0


# ---------------------------------------------------------------------------
# categorize_similarity  (lines 95-103)
# ---------------------------------------------------------------------------


def test_categorize_similarity_exactly_0_8_is_very_high():
    assert categorize_similarity(0.8) == "Very High"


def test_categorize_similarity_above_0_8_is_very_high():
    assert categorize_similarity(1.0) == "Very High"


def test_categorize_similarity_exactly_0_6_is_high():
    assert categorize_similarity(0.6) == "High"


def test_categorize_similarity_between_0_6_and_0_8_is_high():
    assert categorize_similarity(0.75) == "High"


def test_categorize_similarity_exactly_0_4_is_medium():
    assert categorize_similarity(0.4) == "Medium"


def test_categorize_similarity_between_0_4_and_0_6_is_medium():
    assert categorize_similarity(0.55) == "Medium"


def test_categorize_similarity_exactly_0_2_is_low():
    assert categorize_similarity(0.2) == "Low"


def test_categorize_similarity_between_0_2_and_0_4_is_low():
    assert categorize_similarity(0.3) == "Low"


def test_categorize_similarity_below_0_2_is_very_low():
    assert categorize_similarity(0.1) == "Very Low"


def test_categorize_similarity_zero_is_very_low():
    assert categorize_similarity(0.0) == "Very Low"


# ---------------------------------------------------------------------------
# compare_structural_features  (lines 168-191)
# ---------------------------------------------------------------------------


def test_compare_structural_features_same_type_same_arch_same_sections():
    feat = {
        "file_type": "PE",
        "architecture": "x86_64",
        "section_names": [".text", ".data", ".rdata"],
        "imported_dlls": ["kernel32.dll", "ntdll.dll"],
    }
    score = compare_structural_features(feat, feat)
    assert score > 0.95


def test_compare_structural_features_different_type():
    a = {"file_type": "PE", "architecture": "x86_64", "section_names": [], "imported_dlls": []}
    b = {"file_type": "ELF", "architecture": "x86_64", "section_names": [], "imported_dlls": []}
    score = compare_structural_features(a, b)
    # file_type mismatch: no +0.2 for type; arch matches: +0.2
    assert score < 1.0


def test_compare_structural_features_different_arch():
    a = {"file_type": "PE", "architecture": "x86", "section_names": [], "imported_dlls": []}
    b = {"file_type": "PE", "architecture": "x86_64", "section_names": [], "imported_dlls": []}
    score = compare_structural_features(a, b)
    assert score < 1.0


def test_compare_structural_features_sections_contribute_to_score():
    a = {
        "file_type": "PE",
        "architecture": "x86",
        "section_names": [".text", ".data"],
        "imported_dlls": [],
    }
    b = {
        "file_type": "PE",
        "architecture": "x86",
        "section_names": [".text"],
        "imported_dlls": [],
    }
    score = compare_structural_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_structural_features_imports_contribute():
    a = {
        "file_type": "ELF",
        "architecture": "aarch64",
        "section_names": [],
        "imported_dlls": ["libc.so.6", "libpthread.so"],
    }
    b = {
        "file_type": "ELF",
        "architecture": "aarch64",
        "section_names": [],
        "imported_dlls": ["libc.so.6"],
    }
    score = compare_structural_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_structural_features_empty_dicts_returns_valid():
    score = compare_structural_features({}, {})
    assert 0.0 <= score <= 1.0


def test_compare_structural_features_no_sections_no_imports():
    a = {"file_type": "PE", "architecture": "x86", "section_names": [], "imported_dlls": []}
    score = compare_structural_features(a, a)
    # sections and imports are both empty so no jaccard contribution
    assert score <= 1.0


# ---------------------------------------------------------------------------
# compare_function_features  (lines 195-211)
# ---------------------------------------------------------------------------


def test_compare_function_features_identical_returns_high_score():
    feat = {"function_count": 50, "function_names": ["main", "init", "fini"]}
    score = compare_function_features(feat, feat)
    assert score > 0.95


def test_compare_function_features_zero_counts_and_empty_names():
    feat = {"function_count": 0, "function_names": []}
    score = compare_function_features(feat, feat)
    assert 0.0 <= score <= 1.0


def test_compare_function_features_different_counts():
    a = {"function_count": 200, "function_names": ["f1"]}
    b = {"function_count": 10, "function_names": ["f2"]}
    score = compare_function_features(a, b)
    assert 0.0 <= score <= 1.0


def test_compare_function_features_shared_names_increases_score():
    a = {"function_count": 10, "function_names": ["alpha", "beta", "gamma"]}
    b = {"function_count": 10, "function_names": ["alpha", "beta", "delta"]}
    score = compare_function_features(a, b)
    assert 0.0 < score < 1.0


def test_compare_function_features_count_zero_similarity_branch():
    # Both have count 0: normalized_difference_similarity returns 0 for (0,0)
    a = {"function_count": 0, "function_names": ["f1", "f2"]}
    b = {"function_count": 0, "function_names": ["f1", "f3"]}
    score = compare_function_features(a, b)
    assert 0.0 <= score <= 1.0


def test_compare_function_features_names_only_overlap():
    a = {"function_count": 5, "function_names": ["a", "b", "c", "d", "e"]}
    b = {"function_count": 5, "function_names": ["c", "d", "e", "f", "g"]}
    score = compare_function_features(a, b)
    assert 0.0 < score <= 1.0


# ---------------------------------------------------------------------------
# compare_string_features  (lines 215-239)
# ---------------------------------------------------------------------------


def test_compare_string_features_same_signature_returns_one():
    feat = {
        "string_signature": "unique_sig_xyz",
        "api_strings": ["ReadFile"],
        "path_strings": ["C:\\Windows"],
        "registry_strings": [],
    }
    assert compare_string_features(feat, feat) == 1.0


def test_compare_string_features_different_sigs_api_overlap():
    a = {
        "string_signature": "sig_a",
        "api_strings": ["CreateFile", "ReadFile", "WriteFile"],
        "path_strings": [],
        "registry_strings": [],
    }
    b = {
        "string_signature": "sig_b",
        "api_strings": ["CreateFile", "CloseHandle"],
        "path_strings": [],
        "registry_strings": [],
    }
    score = compare_string_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_string_features_path_strings_contribute():
    a = {
        "string_signature": "s1",
        "api_strings": [],
        "path_strings": ["C:\\Windows\\System32", "C:\\Users"],
        "registry_strings": [],
    }
    b = {
        "string_signature": "s2",
        "api_strings": [],
        "path_strings": ["C:\\Windows\\System32"],
        "registry_strings": [],
    }
    score = compare_string_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_string_features_registry_strings_contribute():
    a = {
        "string_signature": "s1",
        "api_strings": [],
        "path_strings": [],
        "registry_strings": ["HKLM\\Software\\Microsoft", "HKCU\\Run"],
    }
    b = {
        "string_signature": "s2",
        "api_strings": [],
        "path_strings": [],
        "registry_strings": ["HKLM\\Software\\Microsoft"],
    }
    score = compare_string_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_string_features_all_empty_no_signature_match():
    a = {"string_signature": "x", "api_strings": [], "path_strings": [], "registry_strings": []}
    b = {"string_signature": "y", "api_strings": [], "path_strings": [], "registry_strings": []}
    score = compare_string_features(a, b)
    assert 0.0 <= score <= 1.0


def test_compare_string_features_fully_disjoint():
    a = {
        "string_signature": "s_a",
        "api_strings": ["CreateFile"],
        "path_strings": ["C:\\A"],
        "registry_strings": ["HKLM\\A"],
    }
    b = {
        "string_signature": "s_b",
        "api_strings": ["DeleteFile"],
        "path_strings": ["C:\\B"],
        "registry_strings": ["HKLM\\B"],
    }
    score = compare_string_features(a, b)
    assert 0.0 <= score < 1.0


# ---------------------------------------------------------------------------
# compare_byte_features  (lines 243-253)
# ---------------------------------------------------------------------------


def test_compare_byte_features_matching_hashes_returns_one():
    data = b"A" * 300
    hashes = calculate_rolling_hash(data, window_size=64)
    feat = {"rolling_hash": hashes}
    score = compare_byte_features(feat, feat)
    assert score == 1.0


def test_compare_byte_features_both_missing_hash_returns_zero():
    score = compare_byte_features({}, {})
    assert score == 0.0


def test_compare_byte_features_one_missing_hash():
    data = b"B" * 300
    hashes = calculate_rolling_hash(data, window_size=64)
    score = compare_byte_features({"rolling_hash": hashes}, {})
    assert score == 0.0


def test_compare_byte_features_different_data():
    h1 = calculate_rolling_hash(b"A" * 300, window_size=64)
    h2 = calculate_rolling_hash(b"Z" * 300, window_size=64)
    score = compare_byte_features({"rolling_hash": h1}, {"rolling_hash": h2})
    assert 0.0 <= score <= 1.0


def test_compare_byte_features_weight_positive():
    h = calculate_rolling_hash(b"X" * 300, window_size=32)
    result = compare_byte_features({"rolling_hash": h}, {"rolling_hash": h})
    # total_weight is 1.0, so result / 1.0 = result
    assert result == 1.0


# ---------------------------------------------------------------------------
# compare_behavioral_features  (lines 257-277)
# ---------------------------------------------------------------------------


def test_compare_behavioral_features_all_zero_returns_zero():
    feat = {
        "crypto_indicators": 0,
        "network_indicators": 0,
        "persistence_indicators": 0,
        "suspicious_apis": 0,
        "crypto_apis": 0,
        "network_apis": 0,
    }
    assert compare_behavioral_features(feat, feat) == 0.0


def test_compare_behavioral_features_identical_nonzero_returns_one():
    feat = {
        "crypto_indicators": 5,
        "network_indicators": 3,
        "persistence_indicators": 2,
        "suspicious_apis": 1,
        "crypto_apis": 4,
        "network_apis": 6,
    }
    assert compare_behavioral_features(feat, feat) == 1.0


def test_compare_behavioral_features_partial_match():
    a = {
        "crypto_indicators": 4,
        "network_indicators": 0,
        "persistence_indicators": 0,
        "suspicious_apis": 0,
        "crypto_apis": 0,
        "network_apis": 0,
    }
    b = {
        "crypto_indicators": 2,
        "network_indicators": 0,
        "persistence_indicators": 0,
        "suspicious_apis": 0,
        "crypto_apis": 0,
        "network_apis": 0,
    }
    score = compare_behavioral_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_behavioral_features_empty_dicts_returns_zero():
    assert compare_behavioral_features({}, {}) == 0.0


def test_compare_behavioral_features_one_nonzero_indicator():
    a = {"network_indicators": 1}
    b = {"network_indicators": 1}
    score = compare_behavioral_features(a, b)
    assert score == 1.0


def test_compare_behavioral_features_asymmetric():
    a = {"crypto_indicators": 10}
    b = {"crypto_indicators": 0}
    score = compare_behavioral_features(a, b)
    # a_val=10 > 0 so indicator is considered; similarity will be 0
    assert score == 0.0


def test_compare_behavioral_features_all_indicators_present():
    a = {
        "crypto_indicators": 2,
        "network_indicators": 1,
        "persistence_indicators": 3,
        "suspicious_apis": 1,
        "crypto_apis": 2,
        "network_apis": 1,
    }
    b = {
        "crypto_indicators": 2,
        "network_indicators": 2,
        "persistence_indicators": 3,
        "suspicious_apis": 1,
        "crypto_apis": 2,
        "network_apis": 1,
    }
    score = compare_behavioral_features(a, b)
    assert 0.0 < score <= 1.0


# ---------------------------------------------------------------------------
# calculate_overall_similarity  (lines 287-304)
# ---------------------------------------------------------------------------


def test_calculate_overall_similarity_all_ones():
    score = calculate_overall_similarity(1.0, 1.0, 1.0, 1.0, 1.0)
    assert abs(score - 1.0) < 0.001


def test_calculate_overall_similarity_all_zeros():
    score = calculate_overall_similarity(0.0, 0.0, 0.0, 0.0, 0.0)
    assert score == 0.0


def test_calculate_overall_similarity_weighted_result():
    # structural=0.2, function=0.3, string=0.2, byte=0.15, behavioral=0.15
    # total_weight = 1.0
    # all 0.5 -> weighted = 0.5
    score = calculate_overall_similarity(0.5, 0.5, 0.5, 0.5, 0.5)
    assert abs(score - 0.5) < 0.001


def test_calculate_overall_similarity_returns_rounded_to_3():
    score = calculate_overall_similarity(0.123456, 0.654321, 0.111111, 0.999, 0.777)
    assert score == round(score, 3)


def test_calculate_overall_similarity_structural_only():
    score = calculate_overall_similarity(1.0, 0.0, 0.0, 0.0, 0.0)
    # structural weight = 0.2, total_weight = 1.0
    assert abs(score - 0.2) < 0.001


def test_calculate_overall_similarity_function_only():
    score = calculate_overall_similarity(0.0, 1.0, 0.0, 0.0, 0.0)
    # function weight = 0.3
    assert abs(score - 0.3) < 0.001


def test_calculate_overall_similarity_mixed_values():
    score = calculate_overall_similarity(0.8, 0.6, 0.7, 0.5, 0.9)
    assert 0.0 < score < 1.0
