from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer


def test_simhash_library_availability():
    result = SimHashAnalyzer.is_available()
    assert isinstance(result, bool)


def test_simhash_is_useful_string():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._is_useful_string("Hello World") is True
    assert analyzer._is_useful_string("   ") is False
    assert analyzer._is_useful_string("12345") is False


def test_simhash_length_category():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._get_length_category(5) == "short"
    assert analyzer._get_length_category(15) == "medium"
    assert analyzer._get_length_category(50) == "long"
    assert analyzer._get_length_category(200) == "very_long"


def test_simhash_classify_opcode_control():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("call") == "control"
    assert analyzer._classify_opcode_type("ret") == "control"


def test_simhash_classify_opcode_data():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("push") == "data"
    assert analyzer._classify_opcode_type("pop") == "data"


def test_simhash_classify_opcode_arithmetic():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("sub") == "arithmetic"
    assert analyzer._classify_opcode_type("mul") == "arithmetic"


def test_simhash_classify_opcode_logical():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._classify_opcode_type("and") == "logical"
    assert analyzer._classify_opcode_type("or") == "logical"
    assert analyzer._classify_opcode_type("xor") == "logical"


def test_simhash_classify_opcode_compare():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("test") == "compare"


def test_simhash_extract_string_features():
    if not SIMHASH_AVAILABLE:
        return
    
    adapter = Mock()
    adapter.get_strings = Mock(return_value=[
        {"string": "Hello World", "vaddr": 0x1000},
        {"string": "Test String", "vaddr": 0x2000}
    ])
    adapter.get_sections = Mock(return_value=[])
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    features = analyzer._extract_string_features()
    
    assert isinstance(features, list)


def test_simhash_extract_opcodes():
    if not SIMHASH_AVAILABLE:
        return
    
    adapter = Mock()
    adapter.get_functions = Mock(return_value=[
        {"offset": 0x1000, "name": "main", "size": 100}
    ])
    adapter.get_disasm = Mock(return_value={
        "ops": [
            {"mnemonic": "mov"},
            {"mnemonic": "add"},
            {"mnemonic": "call"}
        ]
    })
    adapter.cmdj = Mock(return_value=[])
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    features = analyzer._extract_opcodes_features()
    
    assert isinstance(features, list)


def test_simhash_compare_empty_hashes():
    result = SimHashAnalyzer.compare_hashes("", "")
    assert result is None


def test_simhash_compare_none_hashes():
    result = SimHashAnalyzer.compare_hashes(None, None)
    assert result is None


def test_simhash_compare_identical():
    if not SIMHASH_AVAILABLE:
        return
    
    hash1 = "0x123456789abcdef0"
    hash2 = "0x123456789abcdef0"
    
    distance = SimHashAnalyzer.compare_hashes(hash1, hash2)
    
    if distance is not None:
        assert distance == 0


def test_simhash_extract_printable_strings():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    data = b"Hello\x00World\x00Test\x00"
    strings = analyzer._extract_printable_strings(data)
    
    assert isinstance(strings, list)


def test_simhash_min_string_length():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer.min_string_length == 4


def test_simhash_max_instructions():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer.max_instructions_per_function == 500


def test_simhash_get_hash_type():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    assert analyzer._get_hash_type() == "simhash"


def test_simhash_extract_ops_from_dict():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    disasm = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "add"}]}
    ops = analyzer._extract_ops_from_disasm(disasm)
    
    assert len(ops) == 2


def test_simhash_extract_ops_from_list():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = SimHashAnalyzer(adapter, str(sample))
    
    disasm = [{"mnemonic": "mov"}, {"mnemonic": "add"}]
    ops = analyzer._extract_ops_from_disasm(disasm)
    
    assert len(ops) == 2
