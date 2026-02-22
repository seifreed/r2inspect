from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer
from r2inspect.utils.ssdeep_loader import get_ssdeep

pytestmark = pytest.mark.requires_r2


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    return session, R2PipeAdapter(r2)


def test_phase3_simhash_calculate_similarity_real(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(pe_path))
        result = analyzer.analyze()
        assert isinstance(result, dict)

        if SIMHASH_AVAILABLE and result.get("available") and isinstance(result.get("hash_value"), str):
            current_hash = int(result["hash_value"], 16)
            identical = analyzer.calculate_similarity(current_hash, hash_type="combined")
            assert identical["distance"] == 0
            assert identical["similarity_level"] == "identical"

            very_similar = analyzer.calculate_similarity(current_hash ^ 1, hash_type="combined")
            assert very_similar.get("similarity_level") in {"very_similar", "identical"}

            similar = analyzer.calculate_similarity(current_hash ^ ((1 << 10) - 1), hash_type="combined")
            assert similar.get("similarity_level") in {"similar", "very_similar", "identical"}

            somewhat = analyzer.calculate_similarity(
                current_hash ^ ((1 << 20) - 1), hash_type="combined"
            )
            assert somewhat.get("similarity_level") in {
                "somewhat_similar",
                "similar",
                "very_similar",
                "identical",
            }

            different_hash = current_hash ^ ((1 << 40) - 1)
            different = analyzer.calculate_similarity(different_hash, hash_type="combined")
            assert different.get("similarity_level") in {
                "different",
                "somewhat_similar",
                "similar",
                "very_similar",
                "identical",
            }

            invalid = analyzer.calculate_similarity("not-an-int", hash_type="combined")  # type: ignore[arg-type]
            assert "error" in invalid
        else:
            fallback = analyzer.calculate_similarity(0x1234, hash_type="combined")
            assert "error" in fallback
    finally:
        session.close()


def test_phase3_simhash_extract_function_features_real(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(pe_path))
        function_features = analyzer._extract_function_features()
        assert isinstance(function_features, dict)
        assert function_features

        one_name = next(iter(function_features))
        one = function_features[one_name]
        assert "simhash" in one
        assert "simhash_hex" in one
        similar = analyzer._find_similar_functions(function_features, max_distance=64)
        assert isinstance(similar, list)
    finally:
        session.close()


def test_phase3_tlsh_find_similar_sections_real(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = TLSHAnalyzer(adapter=adapter, filename=str(pe_path))
        detailed = analyzer.analyze_sections()
        assert isinstance(detailed, dict)

        pairs = analyzer.find_similar_sections(threshold=1000)
        assert isinstance(pairs, list)
        for pair in pairs[:3]:
            assert "section1" in pair
            assert "section2" in pair
            assert "similarity_score" in pair

        if TLSH_AVAILABLE and detailed.get("binary_tlsh"):
            score = TLSHAnalyzer.compare_hashes(detailed["binary_tlsh"], detailed["binary_tlsh"])
            assert score == 0
    finally:
        session.close()


def test_phase3_impfuzzy_compare_hashes_real(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    try:
        analyzer = ImpfuzzyAnalyzer(adapter=adapter, filepath=str(pe_path))
        result = analyzer.analyze()
        assert isinstance(result, dict)

        if result.get("available") and result.get("hash_value") and get_ssdeep() is not None:
            similarity = ImpfuzzyAnalyzer.compare_hashes(result["hash_value"], result["hash_value"])
            assert isinstance(similarity, int)
            assert 0 <= similarity <= 100
        else:
            assert ImpfuzzyAnalyzer.compare_hashes("", "") is None
    finally:
        session.close()


def test_phase3_telfhash_compare_hashes_real(samples_dir: Path) -> None:
    elf_path = samples_dir / "hello_elf"
    session, adapter = _open_adapter(elf_path)
    try:
        analyzer = TelfhashAnalyzer(adapter=adapter, filepath=str(elf_path))
        result = analyzer.analyze()
        assert isinstance(result, dict)

        file_hash = TelfhashAnalyzer.calculate_telfhash_from_file(str(elf_path))
        if result.get("available") and file_hash and get_ssdeep() is not None:
            similarity = TelfhashAnalyzer.compare_hashes(file_hash, file_hash)
            assert similarity is None or isinstance(similarity, int)
            if isinstance(similarity, int):
                assert 0 <= similarity <= 100
        else:
            assert TelfhashAnalyzer.compare_hashes("", "") is None
    finally:
        session.close()


def test_phase3_telfhash_symbol_probe_helpers_real(samples_dir: Path) -> None:
    elf_path = samples_dir / "hello_elf"
    session, adapter = _open_adapter(elf_path)
    try:
        analyzer = TelfhashAnalyzer(adapter=adapter, filepath=str(elf_path))
        # Exercise _has_elf_symbols negative branches and normal probing.
        assert analyzer._has_elf_symbols(None) is False
        assert analyzer._has_elf_symbols({}) is False

        symbols = analyzer._get_elf_symbols()
        assert isinstance(symbols, list)
        info = adapter.get_file_info()
        has_elf = analyzer._has_elf_symbols(info)
        assert isinstance(has_elf, bool)
    finally:
        session.close()
