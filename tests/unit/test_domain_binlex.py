"""Unit tests for domain/services/binlex.py."""

from __future__ import annotations

import hashlib

from r2inspect.domain.services.binlex import (
    calculate_binary_signature,
    create_signature,
    extract_mnemonic_from_op,
    extract_tokens_from_ops,
    extract_tokens_from_text,
    generate_ngrams,
    normalize_mnemonic,
)


def test_normalize_mnemonic_none_input() -> None:
    assert normalize_mnemonic(None) is None


def test_normalize_mnemonic_empty_string() -> None:
    assert normalize_mnemonic("") is None


def test_normalize_mnemonic_whitespace_only() -> None:
    assert normalize_mnemonic("   ") is None


def test_normalize_mnemonic_valid_mnemonic() -> None:
    assert normalize_mnemonic("  MOV  ") == "mov"
    assert normalize_mnemonic("CALL") == "call"


def test_normalize_mnemonic_html_entities() -> None:
    result = normalize_mnemonic("mov&nbsp;test")
    assert result == "mov test"
    result2 = normalize_mnemonic("push&amp;pop")
    assert result2 == "push&pop"


def test_normalize_mnemonic_ampersand_prefix() -> None:
    assert normalize_mnemonic("&invalid") is None


def test_extract_mnemonic_from_op_with_mnemonic() -> None:
    op = {"mnemonic": "mov"}
    assert extract_mnemonic_from_op(op) == "mov"


def test_extract_mnemonic_from_op_with_opcode() -> None:
    op = {"opcode": "mov eax, ebx"}
    assert extract_mnemonic_from_op(op) == "mov"


def test_extract_mnemonic_from_op_empty() -> None:
    assert extract_mnemonic_from_op({}) is None
    assert extract_mnemonic_from_op({"mnemonic": ""}) is None


def test_extract_tokens_from_ops_basic() -> None:
    ops = [{"mnemonic": "mov"}, {"mnemonic": "push"}, {"mnemonic": "call"}]
    tokens = extract_tokens_from_ops(ops)
    assert tokens == ["mov", "push", "call"]


def test_extract_tokens_from_ops_filters_invalid() -> None:
    ops = [{"mnemonic": "mov"}, {"invalid": True}, {"mnemonic": "call"}]
    tokens = extract_tokens_from_ops(ops)
    assert tokens == ["mov", "call"]


def test_extract_tokens_from_ops_empty_list() -> None:
    assert extract_tokens_from_ops([]) == []


def test_extract_tokens_from_text_basic() -> None:
    text = "mov eax\npush ebx\ncall func"
    tokens = extract_tokens_from_text(text)
    assert tokens == ["mov", "push", "call"]


def test_extract_tokens_from_text_empty() -> None:
    assert extract_tokens_from_text("") == []
    assert extract_tokens_from_text("   \n  \n  ") == []


def test_extract_tokens_from_text_filters_empty_lines() -> None:
    text = "mov\n\n\npush"
    tokens = extract_tokens_from_text(text)
    assert tokens == ["mov", "push"]


def test_generate_ngrams_basic() -> None:
    tokens = ["a", "b", "c", "d"]
    ngrams = generate_ngrams(tokens, 2)
    assert ngrams == ["a b", "b c", "c d"]


def test_generate_ngrams_too_few_tokens() -> None:
    assert generate_ngrams(["a"], 2) == []


def test_generate_ngrams_trigrams() -> None:
    tokens = ["a", "b", "c", "d"]
    ngrams = generate_ngrams(tokens, 3)
    assert ngrams == ["a b c", "b c d"]


def test_create_signature_deterministic() -> None:
    ngrams = ["a b", "b c", "c d"]
    sig1 = create_signature(ngrams)
    sig2 = create_signature(ngrams)
    assert sig1 == sig2
    assert len(sig1) == 64


def test_create_signature_uses_sorted_ngrams() -> None:
    ngrams1 = ["a b", "b c"]
    ngrams2 = ["b c", "a b"]
    assert create_signature(ngrams1) == create_signature(ngrams2)


def test_calculate_binary_signature_basic() -> None:
    function_signatures = {
        "f1": {2: {"signature": "sig1"}},
        "f2": {2: {"signature": "sig2"}},
    }
    result = calculate_binary_signature(function_signatures, [2])
    assert 2 in result
    assert len(result[2]) == 64


def test_calculate_binary_signature_empty() -> None:
    result = calculate_binary_signature({}, [2])
    assert result == {}


def test_calculate_binary_signature_multiple_ngram_sizes() -> None:
    function_signatures = {
        "f1": {2: {"signature": "s1"}, 3: {"signature": "t1"}},
        "f2": {2: {"signature": "s2"}, 3: {"signature": "t2"}},
    }
    result = calculate_binary_signature(function_signatures, [2, 3])
    assert 2 in result
    assert 3 in result
