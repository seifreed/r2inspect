from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.infrastructure.r2_session import R2Session
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer
from r2inspect.infrastructure.ssdeep_loader import get_ssdeep

pytestmark = pytest.mark.requires_r2


# Use the repository-wide session-scoped samples_dir fixture from tests/conftest.py.


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    return session, R2PipeAdapter(r2)


def test_real_simhash_extracts_features_and_self_similarity(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(pe_path))
        result = analyzer.analyze()
        assert isinstance(result, dict)

        function_features = analyzer._extract_function_features()
        assert isinstance(function_features, dict)

        if (
            SIMHASH_AVAILABLE
            and result.get("available")
            and isinstance(result.get("hash_value"), str)
        ):
            current_hash = int(result["hash_value"], 16)
            identical = analyzer.calculate_similarity(current_hash, hash_type="combined")
            assert identical["distance"] == 0
    finally:
        session.close()


def test_real_tlsh_and_telfhash_probe_sections_and_symbols(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    elf_path = samples_dir / "hello_elf"

    pe_session, pe_adapter = _open_adapter(pe_path)
    try:
        tlsh = TLSHAnalyzer(adapter=pe_adapter, filename=str(pe_path))
        detailed = tlsh.analyze_sections()
        assert isinstance(detailed, dict)
        similar = tlsh.find_similar_sections(threshold=1000)
        assert isinstance(similar, list)
        if TLSH_AVAILABLE and detailed.get("binary_tlsh"):
            assert (
                TLSHAnalyzer.compare_hashes(detailed["binary_tlsh"], detailed["binary_tlsh"]) == 0
            )
    finally:
        pe_session.close()

    elf_session, elf_adapter = _open_adapter(elf_path)
    try:
        telfhash = TelfhashAnalyzer(adapter=elf_adapter, filepath=str(elf_path))
        result = telfhash.analyze()
        assert isinstance(result, dict)
        assert isinstance(telfhash._get_elf_symbols(), list)
    finally:
        elf_session.close()


def test_real_impfuzzy_and_telfhash_compare_paths(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    elf_path = samples_dir / "hello_elf"

    pe_session, pe_adapter = _open_adapter(pe_path)
    try:
        impfuzzy = ImpfuzzyAnalyzer(adapter=pe_adapter, filepath=str(pe_path))
        result = impfuzzy.analyze()
        assert isinstance(result, dict)
        if result.get("available") and result.get("hash_value") and get_ssdeep() is not None:
            similarity = ImpfuzzyAnalyzer.compare_hashes(result["hash_value"], result["hash_value"])
            assert isinstance(similarity, int)
    finally:
        pe_session.close()

    elf_session, elf_adapter = _open_adapter(elf_path)
    try:
        telfhash = TelfhashAnalyzer(adapter=elf_adapter, filepath=str(elf_path))
        result = telfhash.analyze()
        assert isinstance(result, dict)
        file_hash = TelfhashAnalyzer.calculate_telfhash_from_file(str(elf_path))
        if result.get("available") and file_hash and get_ssdeep() is not None:
            similarity = TelfhashAnalyzer.compare_hashes(file_hash, file_hash)
            assert similarity is None or isinstance(similarity, int)
    finally:
        elf_session.close()


def test_real_simhash_impfuzzy_and_telfhash_negative_paths(
    samples_dir: Path, tmp_path: Path
) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    elf_path = samples_dir / "hello_elf"
    non_elf_path = tmp_path / "not_elf.bin"
    non_elf_path.write_bytes(b"This is not an ELF binary.\n" * 32)

    pe_session, pe_adapter = _open_adapter(pe_path)
    try:
        analyzer = SimHashAnalyzer(adapter=pe_adapter, filepath=str(pe_path))
        assert isinstance(analyzer._extract_string_features(), list)
        assert isinstance(analyzer._extract_opcodes_features(), list)
        similarity = analyzer.calculate_similarity(0x1234, hash_type="combined")
        assert "error" in similarity or "distance" in similarity
    finally:
        pe_session.close()

    elf_session, elf_adapter = _open_adapter(elf_path)
    try:
        impfuzzy = ImpfuzzyAnalyzer(adapter=elf_adapter, filepath=str(elf_path))
        result = impfuzzy.analyze_imports()
        assert result["available"] is False
        assert result.get("error")
    finally:
        elf_session.close()

    other_session, other_adapter = _open_adapter(non_elf_path)
    try:
        telfhash = TelfhashAnalyzer(adapter=other_adapter, filepath=str(non_elf_path))
        result = telfhash.analyze_symbols()
        assert result["is_elf"] is False
        assert TelfhashAnalyzer.compare_hashes("", "") is None
    finally:
        other_session.close()
