from __future__ import annotations

from r2inspect.modules.function_domain import (
    extract_mnemonics_from_ops,
    extract_mnemonics_from_text,
    machoc_hash_from_mnemonics,
)


def test_extract_mnemonics_from_text_basic_lines() -> None:
    text = "mov eax, ebx\npush ecx\ncall 0x1000\nret"
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push", "call", "ret"]


def test_extract_mnemonics_from_text_empty_returns_empty() -> None:
    assert extract_mnemonics_from_text("") == []
    assert extract_mnemonics_from_text(None) == []  # type: ignore
    assert extract_mnemonics_from_text("   \n\t  ") == []


def test_extract_mnemonics_from_text_ignores_blank_lines() -> None:
    text = "mov eax, ebx\n\npush ecx\n\n"
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push"]


def test_extract_mnemonics_from_text_single_word_per_line() -> None:
    text = "ret\nnop\nhlt"
    result = extract_mnemonics_from_text(text)
    assert result == ["ret", "nop", "hlt"]


def test_extract_mnemonics_from_ops_basic() -> None:
    ops = [{"opcode": "mov eax, 1"}, {"opcode": "ret"}]
    assert extract_mnemonics_from_ops(ops) == ["mov", "ret"]


def test_extract_mnemonics_from_ops_skips_missing_opcode_key() -> None:
    ops = [{"type": "call"}, {"opcode": "push eax"}]
    assert extract_mnemonics_from_ops(ops) == ["push"]


def test_extract_mnemonics_from_ops_skips_empty_opcode() -> None:
    ops = [{"opcode": ""}, {"opcode": "   "}, {"opcode": "nop"}]
    assert extract_mnemonics_from_ops(ops) == ["nop"]


def test_extract_mnemonics_from_ops_non_dict_items_skipped() -> None:
    ops = [{"opcode": "ret"}, "bad_item", 42, None]
    assert extract_mnemonics_from_ops(ops) == ["ret"]


def test_machoc_hash_from_mnemonics_empty_returns_none() -> None:
    assert machoc_hash_from_mnemonics([]) is None


def test_machoc_hash_from_mnemonics_returns_sha256_hex() -> None:
    result = machoc_hash_from_mnemonics(["mov", "push", "ret"])
    assert result is not None
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_machoc_hash_deterministic() -> None:
    mnemonics = ["mov", "push", "call", "ret"]
    h1 = machoc_hash_from_mnemonics(mnemonics)
    h2 = machoc_hash_from_mnemonics(mnemonics)
    assert h1 == h2


def test_machoc_hash_different_for_different_input() -> None:
    h1 = machoc_hash_from_mnemonics(["mov", "ret"])
    h2 = machoc_hash_from_mnemonics(["push", "ret"])
    assert h1 != h2


def test_machoc_hash_single_mnemonic() -> None:
    result = machoc_hash_from_mnemonics(["nop"])
    assert result is not None
    assert len(result) == 64
