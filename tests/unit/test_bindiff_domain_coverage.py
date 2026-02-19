"""Coverage tests for bindiff_domain.py - pure domain utility functions."""

import pytest

from r2inspect.modules.bindiff_domain import (
    build_behavioral_signature,
    build_function_signature,
    build_string_signature,
    build_struct_signature,
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
    has_crypto_indicators,
    has_network_indicators,
    has_persistence_indicators,
    is_crypto_api,
    is_network_api,
    is_suspicious_api,
)


# --- calculate_cyclomatic_complexity ---


def test_cyclomatic_complexity_normal_cfg():
    cfg = {"edges": [{"src": 1, "dst": 2}, {"src": 2, "dst": 3}], "blocks": [1, 2]}
    assert calculate_cyclomatic_complexity(cfg) == 2


def test_cyclomatic_complexity_no_nodes():
    cfg = {"edges": [], "blocks": []}
    assert calculate_cyclomatic_complexity(cfg) == 0


def test_cyclomatic_complexity_empty_dict():
    assert calculate_cyclomatic_complexity({}) == 0


def test_cyclomatic_complexity_invalid_input():
    assert calculate_cyclomatic_complexity(None) == 0  # type: ignore[arg-type]


def test_cyclomatic_complexity_string_input():
    assert calculate_cyclomatic_complexity("not a dict") == 0  # type: ignore[arg-type]


def test_cyclomatic_complexity_with_blocks():
    cfg = {
        "edges": [
            {"src": 1, "dst": 2},
            {"src": 2, "dst": 3},
            {"src": 2, "dst": 4},
        ],
        "blocks": [1, 2, 3, 4],
    }
    assert calculate_cyclomatic_complexity(cfg) == 1


# --- calculate_rolling_hash ---


def test_rolling_hash_basic():
    data = b"A" * 100
    hashes = calculate_rolling_hash(data, window_size=64)
    assert isinstance(hashes, list)
    assert len(hashes) > 0


def test_rolling_hash_short_data():
    data = b"short"
    hashes = calculate_rolling_hash(data, window_size=64)
    assert hashes == []


def test_rolling_hash_returns_at_most_100():
    data = b"X" * 300
    hashes = calculate_rolling_hash(data, window_size=10)
    assert len(hashes) <= 100


def test_rolling_hash_empty():
    assert calculate_rolling_hash(b"", window_size=64) == []


# --- compare_rolling_hashes ---


def test_compare_rolling_hashes_identical():
    data = b"A" * 100
    h = calculate_rolling_hash(data, window_size=64)
    assert compare_rolling_hashes(h, h) == 1.0


def test_compare_rolling_hashes_disjoint():
    h1 = [1, 2, 3]
    h2 = [4, 5, 6]
    assert compare_rolling_hashes(h1, h2) == 0.0


def test_compare_rolling_hashes_partial():
    h1 = [1, 2, 3]
    h2 = [2, 3, 4]
    score = compare_rolling_hashes(h1, h2)
    assert 0.0 < score < 1.0


def test_compare_rolling_hashes_empty_first():
    assert compare_rolling_hashes([], [1, 2]) == 0.0


def test_compare_rolling_hashes_empty_second():
    assert compare_rolling_hashes([1, 2], []) == 0.0


def test_compare_rolling_hashes_both_empty():
    assert compare_rolling_hashes([], []) == 0.0


# --- categorize_similarity ---


def test_categorize_similarity_very_high():
    assert categorize_similarity(0.9) == "Very High"
    assert categorize_similarity(0.8) == "Very High"


def test_categorize_similarity_high():
    assert categorize_similarity(0.7) == "High"
    assert categorize_similarity(0.6) == "High"


def test_categorize_similarity_medium():
    assert categorize_similarity(0.5) == "Medium"
    assert categorize_similarity(0.4) == "Medium"


def test_categorize_similarity_low():
    assert categorize_similarity(0.3) == "Low"
    assert categorize_similarity(0.2) == "Low"


def test_categorize_similarity_very_low():
    assert categorize_similarity(0.1) == "Very Low"
    assert categorize_similarity(0.0) == "Very Low"


# --- indicator detection ---


def test_has_crypto_indicators_positive():
    assert has_crypto_indicators("encrypt data with AES key") is True
    assert has_crypto_indicators("sha256 hash") is True
    assert has_crypto_indicators("RSA decrypt") is True


def test_has_crypto_indicators_negative():
    assert has_crypto_indicators("hello world") is False


def test_has_network_indicators_positive():
    assert has_network_indicators("http://example.com") is True
    assert has_network_indicators("socket connect") is True
    assert has_network_indicators("download file via tcp") is True


def test_has_network_indicators_negative():
    assert has_network_indicators("local file operation") is False


def test_has_persistence_indicators_positive():
    assert has_persistence_indicators("startup service") is True
    assert has_persistence_indicators("autorun registry") is True
    assert has_persistence_indicators("scheduled task") is True


def test_has_persistence_indicators_negative():
    assert has_persistence_indicators("read file") is False


# --- API classification ---


def test_is_suspicious_api_positive():
    assert is_suspicious_api("CreateRemoteThread") is True
    assert is_suspicious_api("WriteProcessMemory") is True
    assert is_suspicious_api("VirtualAllocEx") is True
    assert is_suspicious_api("SetWindowsHookEx") is True
    assert is_suspicious_api("GetKeyState") is True
    assert is_suspicious_api("GetAsyncKeyState") is True
    assert is_suspicious_api("CreateService") is True


def test_is_suspicious_api_negative():
    assert is_suspicious_api("ReadFile") is False
    assert is_suspicious_api("printf") is False


def test_is_crypto_api_positive():
    assert is_crypto_api("CryptAcquireContext") is True
    assert is_crypto_api("CryptCreateHash") is True
    assert is_crypto_api("CryptEncrypt") is True
    assert is_crypto_api("CryptDecrypt") is True


def test_is_crypto_api_negative():
    assert is_crypto_api("OpenFile") is False


def test_is_network_api_positive():
    assert is_network_api("WSAStartup") is True
    assert is_network_api("socket") is True
    assert is_network_api("connect") is True
    assert is_network_api("send") is True
    assert is_network_api("recv") is True
    assert is_network_api("InternetOpen") is True
    assert is_network_api("HttpOpenRequest") is True
    assert is_network_api("HttpSendRequest") is True


def test_is_network_api_negative():
    assert is_network_api("ReadFile") is False


# --- build_* signature builders ---


def test_build_struct_signature():
    features = {"file_type": "PE", "architecture": "x86", "section_names": [".text", ".data"]}
    sig = build_struct_signature(features)
    assert sig == "PE-x86-2"


def test_build_struct_signature_missing_fields():
    sig = build_struct_signature({})
    assert sig == "--0"


def test_build_function_signature():
    features = {"function_count": 10, "function_names": ["func1", "func2", "func3"]}
    sig = build_function_signature(features)
    assert sig == "10-3"


def test_build_function_signature_empty():
    sig = build_function_signature({})
    assert sig == "0-0"


def test_build_string_signature():
    features = {
        "total_strings": 50,
        "api_strings": ["CreateFile", "ReadFile"],
        "path_strings": ["C:\\Windows"],
    }
    sig = build_string_signature(features)
    assert sig == "50-2-1"


def test_build_string_signature_empty():
    sig = build_string_signature({})
    assert sig == "0-0-0"


def test_build_behavioral_signature():
    features = {
        "crypto_indicators": 3,
        "network_indicators": 2,
        "suspicious_apis": 1,
    }
    sig = build_behavioral_signature(features)
    assert sig == "3-2-1"


def test_build_behavioral_signature_empty():
    sig = build_behavioral_signature({})
    assert sig == "0-0-0"


# --- compare_structural_features ---


def test_compare_structural_features_identical():
    features = {
        "file_type": "PE",
        "architecture": "x86",
        "section_names": [".text", ".data"],
        "imported_dlls": ["kernel32.dll"],
    }
    score = compare_structural_features(features, features)
    assert score > 0.9


def test_compare_structural_features_different():
    a = {"file_type": "PE", "architecture": "x86", "section_names": [], "imported_dlls": []}
    b = {"file_type": "ELF", "architecture": "x64", "section_names": [], "imported_dlls": []}
    score = compare_structural_features(a, b)
    assert score < 0.5


def test_compare_structural_features_empty_sections():
    a = {"file_type": "PE", "architecture": "x86", "section_names": [], "imported_dlls": []}
    score = compare_structural_features(a, a)
    assert score <= 1.0


def test_compare_structural_features_with_sections():
    a = {
        "file_type": "PE",
        "architecture": "x86",
        "section_names": [".text", ".data"],
        "imported_dlls": ["kernel32.dll", "user32.dll"],
    }
    b = {
        "file_type": "PE",
        "architecture": "x86",
        "section_names": [".text"],
        "imported_dlls": ["kernel32.dll"],
    }
    score = compare_structural_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_structural_features_empty_dict():
    score = compare_structural_features({}, {})
    assert 0.0 <= score <= 1.0


# --- compare_function_features ---


def test_compare_function_features_identical():
    features = {"function_count": 100, "function_names": ["func1", "func2"]}
    score = compare_function_features(features, features)
    assert score > 0.9


def test_compare_function_features_zero_counts():
    a = {"function_count": 0, "function_names": []}
    b = {"function_count": 0, "function_names": []}
    score = compare_function_features(a, b)
    assert 0.0 <= score <= 1.0


def test_compare_function_features_different_counts():
    a = {"function_count": 100, "function_names": ["f1"]}
    b = {"function_count": 10, "function_names": ["f2"]}
    score = compare_function_features(a, b)
    assert 0.0 <= score <= 1.0


def test_compare_function_features_shared_names():
    a = {"function_count": 10, "function_names": ["f1", "f2", "f3"]}
    b = {"function_count": 10, "function_names": ["f2", "f3", "f4"]}
    score = compare_function_features(a, b)
    assert 0.0 < score < 1.0


# --- compare_string_features ---


def test_compare_string_features_same_signature():
    features = {
        "string_signature": "abc123",
        "api_strings": ["CreateFile"],
        "path_strings": [],
        "registry_strings": [],
    }
    score = compare_string_features(features, features)
    assert score == 1.0


def test_compare_string_features_different_signature():
    a = {
        "string_signature": "sig1",
        "api_strings": ["CreateFile", "ReadFile"],
        "path_strings": ["C:\\Windows"],
        "registry_strings": ["HKLM\\Software"],
    }
    b = {
        "string_signature": "sig2",
        "api_strings": ["CreateFile", "WriteFile"],
        "path_strings": ["C:\\System"],
        "registry_strings": [],
    }
    score = compare_string_features(a, b)
    assert 0.0 < score < 1.0


def test_compare_string_features_empty():
    a = {"string_signature": "sig1", "api_strings": [], "path_strings": [], "registry_strings": []}
    b = {"string_signature": "sig2", "api_strings": [], "path_strings": [], "registry_strings": []}
    score = compare_string_features(a, b)
    assert 0.0 <= score <= 1.0


def test_compare_string_features_with_registry():
    a = {
        "string_signature": "sig1",
        "api_strings": [],
        "path_strings": [],
        "registry_strings": ["HKLM\\Run", "HKCU\\Run"],
    }
    b = {
        "string_signature": "sig2",
        "api_strings": [],
        "path_strings": [],
        "registry_strings": ["HKLM\\Run"],
    }
    score = compare_string_features(a, b)
    assert 0.0 < score <= 1.0


# --- compare_byte_features ---


def test_compare_byte_features_with_identical_hashes():
    data = b"A" * 200
    hashes = calculate_rolling_hash(data, window_size=64)
    features = {"rolling_hash": hashes}
    score = compare_byte_features(features, features)
    assert score == 1.0


def test_compare_byte_features_no_hash():
    score = compare_byte_features({}, {})
    assert score == 0.0


def test_compare_byte_features_one_missing():
    data = b"B" * 200
    hashes = calculate_rolling_hash(data, window_size=64)
    a = {"rolling_hash": hashes}
    b = {}
    score = compare_byte_features(a, b)
    assert score == 0.0


def test_compare_byte_features_different_data():
    h1 = calculate_rolling_hash(b"A" * 200, window_size=64)
    h2 = calculate_rolling_hash(b"B" * 200, window_size=64)
    a = {"rolling_hash": h1}
    b = {"rolling_hash": h2}
    score = compare_byte_features(a, b)
    assert 0.0 <= score <= 1.0


# --- compare_behavioral_features ---


def test_compare_behavioral_features_identical():
    features = {
        "crypto_indicators": 2,
        "network_indicators": 1,
        "persistence_indicators": 0,
        "suspicious_apis": 3,
        "crypto_apis": 1,
        "network_apis": 2,
    }
    score = compare_behavioral_features(features, features)
    assert score == 1.0


def test_compare_behavioral_features_all_zero():
    features = {
        "crypto_indicators": 0,
        "network_indicators": 0,
        "persistence_indicators": 0,
        "suspicious_apis": 0,
        "crypto_apis": 0,
        "network_apis": 0,
    }
    score = compare_behavioral_features(features, features)
    assert score == 0.0


def test_compare_behavioral_features_partial_match():
    a = {"crypto_indicators": 3, "network_indicators": 0, "persistence_indicators": 0,
         "suspicious_apis": 0, "crypto_apis": 0, "network_apis": 0}
    b = {"crypto_indicators": 1, "network_indicators": 0, "persistence_indicators": 0,
         "suspicious_apis": 0, "crypto_apis": 0, "network_apis": 0}
    score = compare_behavioral_features(a, b)
    assert 0.0 < score <= 1.0


def test_compare_behavioral_features_empty_dicts():
    score = compare_behavioral_features({}, {})
    assert score == 0.0


# --- calculate_overall_similarity ---


def test_calculate_overall_similarity_all_ones():
    score = calculate_overall_similarity(1.0, 1.0, 1.0, 1.0, 1.0)
    assert abs(score - 1.0) < 0.01


def test_calculate_overall_similarity_all_zeros():
    score = calculate_overall_similarity(0.0, 0.0, 0.0, 0.0, 0.0)
    assert score == 0.0


def test_calculate_overall_similarity_mixed():
    score = calculate_overall_similarity(0.8, 0.6, 0.7, 0.5, 0.9)
    assert 0.0 < score < 1.0


def test_calculate_overall_similarity_returns_rounded():
    score = calculate_overall_similarity(0.5, 0.5, 0.5, 0.5, 0.5)
    assert score == round(score, 3)
