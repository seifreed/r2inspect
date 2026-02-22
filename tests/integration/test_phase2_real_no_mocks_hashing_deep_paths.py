from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer

pytestmark = pytest.mark.requires_r2


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    return session, R2PipeAdapter(r2)


def test_phase2_simhash_real_extractors_and_similarity(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(pe_path))

        string_features = analyzer._extract_string_features()
        assert isinstance(string_features, list)

        opcode_features = analyzer._extract_opcodes_features()
        assert isinstance(opcode_features, list)

        function_features = analyzer._extract_function_features()
        assert isinstance(function_features, dict)

        if function_features:
            similar = analyzer._find_similar_functions(function_features, max_distance=64)
            assert isinstance(similar, list)

        result = analyzer.analyze()
        assert isinstance(result, dict)
        if result.get("available") and result.get("hash_value"):
            distance = SimHashAnalyzer.compare_hashes(result["hash_value"], result["hash_value"])
            assert distance == 0

        # Must return structured output (either similarity result or clear error).
        similarity = analyzer.calculate_similarity(0x1234, hash_type="combined")
        assert isinstance(similarity, dict)
        assert "error" in similarity or "distance" in similarity
    finally:
        session.close()


def test_phase2_simhash_real_function_opcode_paths(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(pe_path))
        funcs = adapter.get_functions()
        assert isinstance(funcs, list)

        for func in funcs[:5]:
            addr = func.get("offset") or func.get("addr")
            if addr is None:
                continue
            opcodes = analyzer._extract_function_opcodes(int(addr), str(func.get("name", "f")))
            assert isinstance(opcodes, list)

        data_strings = analyzer._extract_data_section_strings()
        assert isinstance(data_strings, list)
    finally:
        session.close()


def test_phase2_impfuzzy_real_pe_and_nonpe_paths(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    elf_path = samples_dir / "hello_elf"

    pe_session, pe_adapter = _open_adapter(pe_path)
    try:
        pe_analyzer = ImpfuzzyAnalyzer(adapter=pe_adapter, filepath=str(pe_path))
        pe_hash = pe_analyzer.analyze()
        assert isinstance(pe_hash, dict)

        pe_imports = pe_analyzer.analyze_imports()
        assert isinstance(pe_imports, dict)
        assert "library_available" in pe_imports

        extracted = pe_analyzer._extract_imports()
        assert isinstance(extracted, list)
    finally:
        pe_session.close()

    elf_session, elf_adapter = _open_adapter(elf_path)
    try:
        non_pe_analyzer = ImpfuzzyAnalyzer(adapter=elf_adapter, filepath=str(elf_path))
        non_pe_hash = non_pe_analyzer.analyze()
        assert isinstance(non_pe_hash, dict)
        assert non_pe_hash.get("error")

        non_pe_imports = non_pe_analyzer.analyze_imports()
        assert non_pe_imports["available"] is False
        assert non_pe_imports.get("error")
    finally:
        elf_session.close()


def test_phase2_telfhash_real_elf_and_nonelf_paths(samples_dir: Path) -> None:
    elf_path = samples_dir / "hello_elf"
    pe_path = samples_dir / "hello_pe.exe"

    elf_session, elf_adapter = _open_adapter(elf_path)
    try:
        elf_analyzer = TelfhashAnalyzer(adapter=elf_adapter, filepath=str(elf_path))
        elf_result = elf_analyzer.analyze_symbols()
        assert isinstance(elf_result, dict)
        assert "is_elf" in elf_result
    finally:
        elf_session.close()

    pe_session, pe_adapter = _open_adapter(pe_path)
    try:
        non_elf_analyzer = TelfhashAnalyzer(adapter=pe_adapter, filepath=str(pe_path))
        non_elf_result = non_elf_analyzer.analyze_symbols()
        assert non_elf_result["is_elf"] is False
        assert "ELF" in (non_elf_result.get("error") or "")
    finally:
        pe_session.close()

    # Static compare path should be safe on empty inputs.
    assert TelfhashAnalyzer.compare_hashes("", "") is None
    assert isinstance(TelfhashAnalyzer.is_available(), bool)


def test_phase2_tlsh_real_find_similar_sections(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = TLSHAnalyzer(adapter=adapter, filename=str(pe_path))
        detailed = analyzer.analyze_sections()
        assert isinstance(detailed, dict)

        similar = analyzer.find_similar_sections(threshold=1000)
        assert isinstance(similar, list)
    finally:
        session.close()
