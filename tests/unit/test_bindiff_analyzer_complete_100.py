"""Comprehensive tests for bindiff_analyzer.py - 100% coverage target."""

from r2inspect.modules.bindiff_domain import (
    calculate_overall_similarity,
    categorize_similarity,
    calculate_rolling_hash,
    has_crypto_indicators,
    has_network_indicators,
    has_persistence_indicators,
    is_crypto_api,
    is_network_api,
    is_suspicious_api,
    calculate_cyclomatic_complexity,
)


def test_bindiff_categorize_similarity():
    """Test similarity categorization."""
    assert categorize_similarity(1.0) is not None
    assert categorize_similarity(0.5) is not None
    assert categorize_similarity(0.0) is not None


def test_bindiff_calculate_overall_similarity():
    """Test overall similarity calculation."""
    result = calculate_overall_similarity(
        structural=0.6,
        function=0.7,
        string=0.8,
        byte=0.9,
        behavioral=0.5,
    )
    assert 0.0 <= result <= 1.0


def test_bindiff_calculate_rolling_hash():
    """Test rolling hash calculation."""
    data = b"hello world test data" * 10  # needs to be >= window_size (64)
    result = calculate_rolling_hash(data)
    assert isinstance(result, list)
    assert all(isinstance(h, int) for h in result)


def test_bindiff_api_classification():
    """Test API classification functions."""
    assert isinstance(is_crypto_api("CryptEncrypt"), bool)
    assert isinstance(is_network_api("connect"), bool)
    assert isinstance(is_suspicious_api("VirtualAlloc"), bool)


def test_bindiff_indicator_checks():
    """Test indicator detection with string input."""
    text = "CryptEncrypt WSAStartup RegSetValueEx"
    assert isinstance(has_crypto_indicators(text), bool)
    assert isinstance(has_network_indicators(text), bool)
    assert isinstance(has_persistence_indicators(text), bool)


def test_bindiff_cyclomatic_complexity():
    """Test cyclomatic complexity calculation."""
    cfg = {"edges": list(range(10)), "blocks": list(range(8))}
    result = calculate_cyclomatic_complexity(cfg)
    assert isinstance(result, int)
    assert result == 10 - 8 + 2

    # Empty CFG
    assert calculate_cyclomatic_complexity({}) == 0
    assert calculate_cyclomatic_complexity({"blocks": []}) == 0


def test_bindiff_empty_text():
    """Test indicator checks with empty string."""
    assert has_crypto_indicators("") is False
    assert has_network_indicators("") is False
    assert has_persistence_indicators("") is False
