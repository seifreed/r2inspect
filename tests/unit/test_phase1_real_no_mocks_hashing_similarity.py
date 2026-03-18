from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.infrastructure.r2_session import R2Session
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer
from r2inspect.modules.binlex_analyzer import BinlexAnalyzer
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer


def _tmp_file(tmp_path: Path, name: str = "sample.bin", size: int = 256) -> Path:
    path = tmp_path / name
    path.write_bytes(bytes(range(256))[:size])
    return path


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    return session, R2PipeAdapter(r2)


def test_phase1_tlsh_binary_and_helpers_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=200)
    analyzer = TLSHAnalyzer(adapter=None, filename=str(sample))

    result = analyzer.analyze()
    if TLSH_AVAILABLE:
        assert result["available"] is True
        assert result["hash_type"] == "tlsh"
        assert result["method_used"] == "python_library"
        assert result["hash_value"]
        assert result["binary_tlsh"] == result["hash_value"]
    else:
        assert result["available"] is False
        assert "TLSH library not available" in (result.get("error") or "")

    detailed = analyzer.analyze_sections()
    if TLSH_AVAILABLE:
        assert detailed["available"] is True
        assert detailed["stats"]["sections_analyzed"] == 0
        assert detailed["stats"]["functions_analyzed"] == 0
    else:
        assert detailed["available"] is False

    assert analyzer._calculate_tlsh_from_hex("") is None
    assert analyzer._calculate_tlsh_from_hex("00") is None

    if TLSH_AVAILABLE and result.get("hash_value"):
        score = analyzer.compare_tlsh(result["hash_value"], result["hash_value"])
        assert isinstance(score, int)
        assert score == 0
    assert analyzer.compare_tlsh("", "abc") is None


def test_phase1_telfhash_symbol_filters_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=128)
    analyzer = TelfhashAnalyzer(adapter=None, filepath=str(sample))

    result = analyzer.analyze()
    assert result["hash_type"] == "telfhash"
    if result["available"]:
        assert "hash_value" in result
    else:
        assert result["error"]

    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "main"},
        {"type": "OBJECT", "bind": "WEAK", "name": "data_var"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local_only"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "__hidden"},
        {"type": "NOTYPE", "bind": "GLOBAL", "name": "ignored"},
        {"type": "FUNC", "bind": "GLOBAL", "name": ""},
    ]
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    names = analyzer._extract_symbol_names(filtered)

    assert {"main", "data_var"}.issubset(set(names))
    assert "local_only" not in names
    assert "__hidden" not in names
    assert analyzer._should_skip_symbol("_start") is True
    assert analyzer._should_skip_symbol("my_exported_func") is False

    assert TelfhashAnalyzer.compare_hashes("", "x") is None
    telfhash_from_file = TelfhashAnalyzer.calculate_telfhash_from_file(str(sample))
    assert telfhash_from_file in {None, "-", result.get("hash_value")}


def test_phase1_impfuzzy_import_processing_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, "pe_like.bin", size=64)
    analyzer = ImpfuzzyAnalyzer(adapter=None, filepath=str(sample))

    processed = analyzer._process_imports(
        [
            {"libname": "KERNEL32.dll", "name": "CreateFileA"},
            {"lib": "USER32.dll", "func": "MessageBoxA"},
            {"library": "NTDLL.dll", "function": "RtlAllocateHeap"},
            {"module": "ws2_32.dll", "symbol": "ord_1234"},
            {"libname": "ADVAPI32.dll", "name": "RegOpenKeyA"},
        ]
    )

    assert "kernel32.createfilea" in processed
    assert "user32.messageboxa" in processed
    assert "ntdll.rtlallocateheap" in processed
    assert "advapi32.regopenkeya" in processed
    assert all("ord_" not in entry for entry in processed)
    assert processed == sorted(processed)

    result = analyzer.analyze_imports()
    assert isinstance(result, dict)
    assert "library_available" in result

    assert ImpfuzzyAnalyzer.compare_hashes("", "abc") is None
    _ = ImpfuzzyAnalyzer.calculate_impfuzzy_from_file(str(sample))


def test_phase1_simhash_helpers_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=180)
    analyzer = SimHashAnalyzer(adapter=None, filepath=str(sample))

    assert analyzer._get_length_category(5) == "short"
    assert analyzer._get_length_category(20) == "medium"
    assert analyzer._get_length_category(40) == "long"
    assert analyzer._get_length_category(200) == "very_long"

    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("xor") == "logical"
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("rep") == "string"
    assert analyzer._classify_opcode_type("nop") == "other"

    strings = analyzer._extract_printable_strings(b"abc\x00hello1234\x00xyz\x00printable")
    assert "hello1234" in strings
    assert "printable" in strings

    assert analyzer._is_useful_string("simple_api_name") is True
    assert analyzer._is_useful_string("1234567890") is False
    assert analyzer._is_useful_string("deadbeefcafebabe") is False

    assert analyzer._get_prev_mnemonic([{"mnemonic": "mov"}, {"mnemonic": "jmp"}], 1) == "mov"
    assert analyzer._get_prev_mnemonic([], 0) is None
    assert analyzer._extract_ops_from_disasm({"ops": [{"mnemonic": "ret"}]}) == [
        {"mnemonic": "ret"}
    ]
    assert analyzer._extract_ops_from_disasm([{"mnemonic": "ret"}]) == [{"mnemonic": "ret"}]
    assert analyzer._extract_ops_from_disasm(None) == []

    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert result["hash_type"] == "simhash"


def test_phase1_binlex_signature_paths_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=220)
    analyzer = BinlexAnalyzer(adapter=None, filepath=str(sample))

    assert analyzer._normalize_mnemonic(" MOV ") == "mov"
    assert analyzer._normalize_mnemonic("&nbsp;") == " "
    assert analyzer._extract_mnemonic_from_op({"mnemonic": "call"}) == "call"
    assert analyzer._extract_mnemonic_from_op({"opcode": "jmp 0x401000"}) == "jmp"
    assert analyzer._extract_mnemonic_from_op({"opcode": ""}) is None

    tokens = analyzer._extract_tokens_from_ops(
        [{"mnemonic": "mov"}, {"opcode": "jmp 0x10"}, {"mnemonic": "ret"}]
    )
    assert tokens == ["mov", "jmp", "ret"]

    ngrams = analyzer._generate_ngrams(tokens, 2)
    assert ngrams == ["mov jmp", "jmp ret"]
    assert analyzer._generate_ngrams(tokens, 5) == []

    sig1 = analyzer._create_signature(["a b", "b c"])
    sig2 = analyzer._create_signature(["b c", "a b"])
    assert sig1 == sig2
    assert analyzer.compare_functions(sig1, sig2) is True
    assert analyzer.get_function_similarity_score(["a", "b"], ["a", "c"]) > 0.0
    assert analyzer.get_function_similarity_score([], []) == 1.0

    bin_sig = analyzer._calculate_binary_signature(
        {
            "f1": {2: {"signature": sig1}},
            "f2": {2: {"signature": sig2}, 3: {"signature": "x" * 64}},
        },
        [2, 3, 4],
    )
    assert 2 in bin_sig
    assert 3 in bin_sig
    assert 4 not in bin_sig

    signatures, groups = analyzer._collect_signatures_for_size(
        {
            "f1": {2: {"signature": sig1}},
            "f2": {2: {"signature": sig1}},
            "f3": {2: {"signature": "y" * 64}},
        },
        2,
    )
    assert len(signatures) == 2
    similar_groups = analyzer._build_similar_groups(groups)
    assert any(g["count"] == 2 for g in similar_groups)

    from collections import Counter, defaultdict

    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    analyzer._accumulate_ngrams(all_ngrams, {2: {"ngrams": ["mov jmp", "jmp ret"]}}, [2])  # type: ignore[arg-type]
    assert 2 in all_ngrams

    assert analyzer.get_function_similarity_score([], ["a"]) == 0.0
    assert analyzer.get_function_similarity_score([["a"]], [["a"]]) == 0.0  # type: ignore[list-item]


def test_phase1_binlex_grouping_and_top_ngrams_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=180)
    analyzer = BinlexAnalyzer(adapter=None, filepath=str(sample))

    function_signatures = {
        "fa": {2: {"signature": "a" * 64, "ngrams": ["mov jmp"]}},
        "fb": {2: {"signature": "a" * 64, "ngrams": ["mov jmp", "jmp ret"]}},
        "fc": {2: {"signature": "b" * 64, "ngrams": ["push pop"]}},
    }
    unique_signatures, similar_functions = analyzer._build_signature_groups(
        function_signatures, [2]
    )
    assert unique_signatures[2] == 2
    assert similar_functions[2]

    from collections import Counter, defaultdict

    all_ngrams = defaultdict(Counter)
    analyzer._accumulate_ngrams(all_ngrams, function_signatures["fa"], [2])
    analyzer._accumulate_ngrams(all_ngrams, function_signatures["fb"], [2])
    top = analyzer._collect_top_ngrams(all_ngrams, [2, 3])
    assert 2 in top
    assert 3 not in top


def test_phase1_binbloom_serialization_and_stats_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=240)
    analyzer = BinbloomAnalyzer(adapter=None, filepath=str(sample))

    assert analyzer._normalize_mnemonic(" MOV ") == "mov"
    assert analyzer._normalize_mnemonic("") is None

    signature = analyzer._bloom_to_signature(["mov", "call", "ret", "mov"])
    assert len(signature) == 64
    assert signature == analyzer._bloom_to_signature(["mov", "call", "ret", "mov"])

    groups = analyzer._group_functions_by_signature(
        {
            "f&nbsp;1": {"signature": "abc"},
            "f&amp;2": {"signature": "abc"},
            "f3": {"signature": "def"},
        }
    )
    assert groups["abc"] == ["f 1", "f&2"]
    similar = analyzer._build_similar_groups(groups)
    assert any(entry["count"] == 2 for entry in similar)

    if BLOOM_AVAILABLE:
        bloom1 = analyzer._build_bloom_filter(["mov", "call", "ret"], capacity=64, error_rate=0.01)
        bloom2 = analyzer._build_bloom_filter(["mov", "call", "ret"], capacity=64, error_rate=0.01)
        bloom3 = analyzer._build_bloom_filter(["push", "pop"], capacity=64, error_rate=0.01)

        encoded = analyzer._serialize_bloom(bloom1)
        decoded = BinbloomAnalyzer.deserialize_bloom(encoded)
        assert decoded is not None

        serialized_many = analyzer._serialize_blooms({"f1": bloom1, "f2": bloom2})
        assert set(serialized_many.keys()) == {"f1", "f2"}

        stats = analyzer._calculate_bloom_stats({"f1": bloom1, "f2": bloom2}, 64, 0.01)
        assert stats["total_filters"] == 2
        assert 0.0 <= stats["average_fill_rate"] <= 1.0

        assert 0.0 <= analyzer.compare_bloom_filters(bloom1, bloom2) <= 1.0
        assert 0.0 <= analyzer.compare_bloom_filters(bloom1, bloom3) <= 1.0

        binary_bloom = analyzer._create_binary_bloom({"mov", "call", "ret"}, 64, 0.01)
        assert binary_bloom is not None

        similar_groups = analyzer._find_similar_functions(
            {
                "f1": {"signature": "a" * 64},
                "f2": {"signature": "a" * 64},
                "f3": {"signature": "b" * 64},
            }
        )
        assert any(group["count"] == 2 for group in similar_groups)

        assert analyzer._calculate_bloom_stats({}, 64, 0.01) == {}
        assert analyzer._create_binary_bloom({"x"}, 0, 0.01) is None

    assert BinbloomAnalyzer.deserialize_bloom("not-base64") is None


def test_phase1_binbloom_deserialize_validation_real_no_mocks() -> None:
    import base64
    import json

    bad_payloads = [
        {},  # missing keys
        {"version": 2, "error_rate": 0.01, "capacity": 32, "count": 1, "bitarray": [True]},
        {"version": 1, "error_rate": 2.0, "capacity": 32, "count": 1, "bitarray": [True]},
        {"version": 1, "error_rate": 0.01, "capacity": 0, "count": 1, "bitarray": [True]},
        {"version": 1, "error_rate": 0.01, "capacity": 32, "count": 99, "bitarray": [True]},
        {"version": 1, "error_rate": 0.01, "capacity": 32, "count": 1, "bitarray": "not-a-list"},
    ]
    for payload in bad_payloads:
        b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        assert BinbloomAnalyzer.deserialize_bloom(b64) is None


def test_phase1_simhash_feature_paths_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=120)
    analyzer = SimHashAnalyzer(adapter=None, filepath=str(sample))

    empty_hash, method, error = analyzer._calculate_hash()
    assert empty_hash is None
    assert method is None
    assert error

    detailed = analyzer.analyze_detailed()
    assert isinstance(detailed, dict)
    assert "available" in detailed

    groups = analyzer._find_similar_functions(
        {
            "f1": {"simhash": 0x1111},
            "f2": {"simhash": 0x1111},
            "f3": {"simhash": 0x2222},
        },
        max_distance=0,
    )
    assert any(group["count"] >= 2 for group in groups) or groups == []


def test_phase1_from_file_entrypoints_real_no_mocks(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    elf_path = samples_dir / "hello_elf"

    simhash_result = SimHashAnalyzer.calculate_simhash_from_file(str(pe_path))
    assert simhash_result is None or isinstance(simhash_result, dict)
    if isinstance(simhash_result, dict):
        assert simhash_result.get("hash_type") == "simhash"

    binlex_result = BinlexAnalyzer.calculate_binlex_from_file(str(pe_path), ngram_sizes=[2])
    assert binlex_result is None or isinstance(binlex_result, dict)
    if isinstance(binlex_result, dict):
        assert "analyzer" in binlex_result

    binbloom_result = BinbloomAnalyzer.calculate_binbloom_from_file(
        str(pe_path), capacity=64, error_rate=0.01
    )
    assert binbloom_result is None or isinstance(binbloom_result, dict)
    if isinstance(binbloom_result, dict):
        assert "analyzer" in binbloom_result

    telfhash_value = TelfhashAnalyzer.calculate_telfhash_from_file(str(elf_path))
    assert telfhash_value is None or isinstance(telfhash_value, str)

    impfuzzy_value = ImpfuzzyAnalyzer.calculate_impfuzzy_from_file(str(pe_path))
    assert impfuzzy_value is None or isinstance(impfuzzy_value, str)


def test_phase1_impfuzzy_and_tlsh_detailed_real_no_mocks(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        imp = ImpfuzzyAnalyzer(adapter=adapter, filepath=str(pe_path))
        imports_result = imp.analyze_imports()
        assert isinstance(imports_result, dict)
        assert "library_available" in imports_result
        if imports_result["library_available"] and imports_result.get("available"):
            assert isinstance(imports_result.get("imports_processed"), list)
            assert imports_result.get("import_count", 0) >= 0

        tlsh = TLSHAnalyzer(adapter=adapter, filename=str(pe_path))
        section_result = tlsh.analyze_sections()
        assert isinstance(section_result, dict)
        if section_result.get("available"):
            assert "section_tlsh" in section_result
            assert "function_tlsh" in section_result
            similar = tlsh.find_similar_sections(threshold=1000)
            assert isinstance(similar, list)
    finally:
        session.close()


def test_phase1_tlsh_similarity_levels_and_compare_real_no_mocks(tmp_path: Path) -> None:
    sample = _tmp_file(tmp_path, size=200)
    analyzer = TLSHAnalyzer(adapter=None, filename=str(sample))
    hash_value = analyzer._calculate_binary_tlsh()

    if TLSH_AVAILABLE and hash_value:
        assert TLSHAnalyzer.compare_hashes(hash_value, hash_value) == 0
    assert TLSHAnalyzer.compare_hashes("", "") is None
    assert TLSHAnalyzer.is_available() == TLSH_AVAILABLE

    assert TLSHAnalyzer.get_similarity_level(None) == "Unknown"
    assert TLSHAnalyzer.get_similarity_level(0) == "Identical"
    assert TLSHAnalyzer.get_similarity_level(20) == "Very Similar"
    assert TLSHAnalyzer.get_similarity_level(40) == "Similar"
    assert TLSHAnalyzer.get_similarity_level(90) == "Somewhat Similar"
    assert TLSHAnalyzer.get_similarity_level(180) == "Different"
    assert TLSHAnalyzer.get_similarity_level(300) == "Very Different"


def test_phase1_tlsh_small_file_and_read_error_real_no_mocks(tmp_path: Path) -> None:
    tiny = _tmp_file(tmp_path, name="tiny.bin", size=16)
    analyzer = TLSHAnalyzer(adapter=None, filename=str(tiny))
    result = analyzer.analyze()

    if TLSH_AVAILABLE:
        assert result["available"] is True
        assert result["hash_value"] is None
        assert "returned no hash" in (result.get("error") or "")
    else:
        assert result["available"] is False

    missing = tmp_path / "missing.bin"
    missing_analyzer = TLSHAnalyzer(adapter=None, filename=str(missing))
    assert missing_analyzer._calculate_binary_tlsh() is None
