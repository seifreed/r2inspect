#!/usr/bin/env python3
"""Comprehensive tests for function_domain.py module."""

from r2inspect.modules.function_domain import (
    extract_mnemonics_from_ops,
    extract_mnemonics_from_text,
    machoc_hash_from_mnemonics,
)


def test_extract_mnemonics_from_ops_basic():
    """Test extracting mnemonics from ops list."""
    ops = [
        {"opcode": "mov eax, ebx"},
        {"opcode": "push ecx"},
        {"opcode": "call 0x1000"},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push", "call"]


def test_extract_mnemonics_from_ops_with_whitespace():
    """Test extracting mnemonics with leading/trailing whitespace."""
    ops = [
        {"opcode": "  mov eax, ebx  "},
        {"opcode": "\tpush ecx\n"},
        {"opcode": "  jmp 0x2000"},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push", "jmp"]


def test_extract_mnemonics_from_ops_empty_opcode():
    """Test extracting mnemonics with empty opcodes."""
    ops = [
        {"opcode": "mov eax, ebx"},
        {"opcode": ""},
        {"opcode": "   "},
        {"opcode": "push ecx"},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push"]


def test_extract_mnemonics_from_ops_missing_opcode():
    """Test extracting mnemonics when opcode key is missing."""
    ops = [
        {"opcode": "mov eax, ebx"},
        {"type": "call"},
        {"opcode": "push ecx"},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push"]


def test_extract_mnemonics_from_ops_empty_list():
    """Test extracting mnemonics from empty ops list."""
    result = extract_mnemonics_from_ops([])
    assert result == []


def test_extract_mnemonics_from_ops_non_dict_items():
    """Test extracting mnemonics with non-dict items."""
    ops = [
        {"opcode": "mov eax, ebx"},
        "invalid",
        {"opcode": "push ecx"},
        None,
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push"]


def test_extract_mnemonics_from_ops_complex_instructions():
    """Test extracting mnemonics from complex instructions."""
    ops = [
        {"opcode": "add dword ptr [ebp-4], 0x10"},
        {"opcode": "lea eax, [ebp-8]"},
        {"opcode": "test eax, eax"},
        {"opcode": "jne 0x1000"},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["add", "lea", "test", "jne"]


def test_extract_mnemonics_from_text_basic():
    """Test extracting mnemonics from text."""
    text = """mov eax, ebx
push ecx
call 0x1000
ret"""
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push", "call", "ret"]


def test_extract_mnemonics_from_text_with_whitespace():
    """Test extracting mnemonics from text with extra whitespace."""
    text = """  mov eax, ebx  
    push ecx
  call 0x1000
    ret  """
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push", "call", "ret"]


def test_extract_mnemonics_from_text_empty():
    """Test extracting mnemonics from empty text."""
    result = extract_mnemonics_from_text("")
    assert result == []


def test_extract_mnemonics_from_text_whitespace_only():
    """Test extracting mnemonics from whitespace-only text."""
    result = extract_mnemonics_from_text("   \n\t\n   ")
    assert result == []


def test_extract_mnemonics_from_text_empty_lines():
    """Test extracting mnemonics from text with empty lines."""
    text = """mov eax, ebx

push ecx

call 0x1000
"""
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push", "call"]


def test_extract_mnemonics_from_text_single_line():
    """Test extracting mnemonics from single line."""
    text = "mov eax, ebx"
    result = extract_mnemonics_from_text(text)
    assert result == ["mov"]


def test_extract_mnemonics_from_text_complex_operands():
    """Test extracting mnemonics with complex operands."""
    text = """add dword ptr [ebp-4], 0x10
lea eax, [ebp-8]
test eax, eax
jne 0x1000"""
    result = extract_mnemonics_from_text(text)
    assert result == ["add", "lea", "test", "jne"]


def test_extract_mnemonics_from_text_with_comments():
    """Test extracting mnemonics from text with comments."""
    text = """mov eax, ebx ; comment
push ecx
call 0x1000"""
    result = extract_mnemonics_from_text(text)
    assert result == ["mov", "push", "call"]


def test_machoc_hash_from_mnemonics_basic():
    """Test generating MACHOC hash from mnemonics."""
    mnemonics = ["mov", "push", "call", "ret"]
    result = machoc_hash_from_mnemonics(mnemonics)
    assert result is not None
    assert isinstance(result, str)
    assert len(result) == 64


def test_machoc_hash_from_mnemonics_consistent():
    """Test MACHOC hash is consistent for same input."""
    mnemonics = ["mov", "push", "call", "ret"]
    hash1 = machoc_hash_from_mnemonics(mnemonics)
    hash2 = machoc_hash_from_mnemonics(mnemonics)
    assert hash1 == hash2


def test_machoc_hash_from_mnemonics_different():
    """Test MACHOC hash is different for different input."""
    mnemonics1 = ["mov", "push", "call", "ret"]
    mnemonics2 = ["mov", "pop", "jmp", "ret"]
    hash1 = machoc_hash_from_mnemonics(mnemonics1)
    hash2 = machoc_hash_from_mnemonics(mnemonics2)
    assert hash1 != hash2


def test_machoc_hash_from_mnemonics_empty():
    """Test MACHOC hash with empty mnemonics."""
    result = machoc_hash_from_mnemonics([])
    assert result is None


def test_machoc_hash_from_mnemonics_single():
    """Test MACHOC hash with single mnemonic."""
    mnemonics = ["ret"]
    result = machoc_hash_from_mnemonics(mnemonics)
    assert result is not None
    assert isinstance(result, str)
    assert len(result) == 64


def test_machoc_hash_from_mnemonics_order_matters():
    """Test MACHOC hash changes with different order."""
    mnemonics1 = ["mov", "push", "call"]
    mnemonics2 = ["push", "mov", "call"]
    hash1 = machoc_hash_from_mnemonics(mnemonics1)
    hash2 = machoc_hash_from_mnemonics(mnemonics2)
    assert hash1 != hash2


def test_machoc_hash_from_mnemonics_large_list():
    """Test MACHOC hash with large mnemonic list."""
    mnemonics = ["mov"] * 1000 + ["push"] * 500 + ["call"] * 250
    result = machoc_hash_from_mnemonics(mnemonics)
    assert result is not None
    assert isinstance(result, str)
    assert len(result) == 64


def test_extract_mnemonics_integration():
    """Test integration of extract and hash functions."""
    ops = [
        {"opcode": "mov eax, ebx"},
        {"opcode": "push ecx"},
        {"opcode": "call 0x1000"},
        {"opcode": "ret"},
    ]
    mnemonics = extract_mnemonics_from_ops(ops)
    hash_result = machoc_hash_from_mnemonics(mnemonics)
    assert hash_result is not None
    assert len(hash_result) == 64


def test_extract_mnemonics_from_text_integration():
    """Test integration of text extraction and hash."""
    text = """mov eax, ebx
push ecx
call 0x1000
ret"""
    mnemonics = extract_mnemonics_from_text(text)
    hash_result = machoc_hash_from_mnemonics(mnemonics)
    assert hash_result is not None
    assert len(hash_result) == 64


def test_extract_mnemonics_from_ops_hex_values():
    """Test extracting mnemonics with hex values in opcodes."""
    ops = [
        {"opcode": "0x48 0x89 0xe5"},
        {"opcode": "0x55"},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert len(result) == 2


def test_machoc_hash_special_characters():
    """Test MACHOC hash with special mnemonic names."""
    mnemonics = ["nop", "int3", "syscall", "ret"]
    result = machoc_hash_from_mnemonics(mnemonics)
    assert result is not None
    assert len(result) == 64


def test_extract_mnemonics_from_text_none():
    """Test extract mnemonics from None text."""
    result = extract_mnemonics_from_text(None)
    assert result == []


def test_extract_mnemonics_from_ops_with_extra_fields():
    """Test extracting mnemonics from ops with extra fields."""
    ops = [
        {"opcode": "mov eax, ebx", "type": "mov", "size": 2},
        {"opcode": "push ecx", "type": "push", "size": 1},
    ]
    result = extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push"]
