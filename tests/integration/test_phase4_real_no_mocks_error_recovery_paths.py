from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.infrastructure.r2_session import R2Session
from r2inspect.modules.binlex_analyzer import BinlexAnalyzer
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.testing.fixtures import resolve_fixture_source_root, sync_sample_fixtures

pytestmark = pytest.mark.requires_r2


@pytest.fixture
def samples_dir(tmp_path: Path) -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    source_root = resolve_fixture_source_root(repo_root)
    if source_root is None:
        pytest.skip("sample fixtures are not available")
    fixtures_dir = tmp_path / "fixtures"
    sync_sample_fixtures(fixtures_dir, source_root, copy_files=True)
    return fixtures_dir


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    return session, R2PipeAdapter(r2)


def test_phase4_telfhash_real_error_recovery_paths(samples_dir: Path) -> None:
    elf_path = samples_dir / "hello_elf"
    session, adapter = _open_adapter(elf_path)
    analyzer = TelfhashAnalyzer(adapter=adapter, filepath=str(elf_path))

    # Probe helper branches while session is alive.
    assert analyzer._has_elf_symbols(None) is False
    assert analyzer._has_elf_symbols({}) is False
    assert analyzer._has_elf_symbols({"bin": None}) is False
    assert analyzer._should_skip_symbol("a") is True

    # After closing the real r2 session, analyzer should fail safely.
    session.close()
    assert isinstance(analyzer._is_elf_file(), bool)
    assert isinstance(analyzer._get_elf_symbols(), list)

    missing = TelfhashAnalyzer.calculate_telfhash_from_file("/definitely/missing/file")
    assert missing is None or missing == []


def test_phase4_simhash_real_error_recovery_paths(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(pe_path))

    # Close real session and ensure methods recover with safe defaults.
    session.close()
    assert analyzer._extract_opcodes_features() == []
    assert analyzer._extract_function_features() == {}

    invalid_similarity = analyzer.calculate_similarity("not-an-int", hash_type="combined")  # type: ignore[arg-type]
    assert "error" in invalid_similarity

    assert SimHashAnalyzer.compare_hashes("invalid-hex", "0x1234") is None


def test_phase4_binlex_real_token_extractors_and_recovery(samples_dir: Path) -> None:
    pe_path = samples_dir / "hello_pe.exe"
    session, adapter = _open_adapter(pe_path)
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=str(pe_path))

    functions = analyzer._extract_functions()
    assert isinstance(functions, list)
    assert functions

    first = functions[0]
    addr = first.get("addr")
    assert isinstance(addr, int)

    tokens_pdfj = analyzer._extract_tokens_from_pdfj(addr, str(first.get("name", "f")))
    assert isinstance(tokens_pdfj, list)

    tokens_pdj = analyzer._extract_tokens_from_pdj(addr, str(first.get("name", "f")))
    assert isinstance(tokens_pdj, list)

    tokens_text = analyzer._extract_tokens_from_text(addr, str(first.get("name", "f")))
    assert isinstance(tokens_text, list)

    combined = analyzer._extract_instruction_tokens(addr, str(first.get("name", "f")))
    assert isinstance(combined, list)

    session.close()

    # Closed session path should fail safely.
    recovered = analyzer._extract_instruction_tokens(addr, str(first.get("name", "f")))
    assert recovered == []


def test_phase4_impfuzzy_real_invalid_input_paths(samples_dir: Path) -> None:
    elf_path = samples_dir / "hello_elf"
    analyzer = ImpfuzzyAnalyzer(adapter=None, filepath=str(elf_path))

    # With no adapter/r2 context, imports extraction should fail safely.
    extracted = analyzer._extract_imports()
    assert extracted == []

    # Malformed import entries should be handled by exception-safe path.
    processed = analyzer._process_imports([42])  # type: ignore[list-item]
    assert processed == []

    # Invalid compare payload should fail safely.
    malformed_compare = ImpfuzzyAnalyzer.compare_hashes("not-a-hash", "%%%")
    assert malformed_compare is None


def test_phase4_telfhash_real_adapter_none_probe_paths(samples_dir: Path) -> None:
    elf_path = samples_dir / "hello_elf"
    pe_path = samples_dir / "hello_pe.exe"

    elf_analyzer = TelfhashAnalyzer(adapter=None, filepath=str(elf_path))
    assert elf_analyzer._is_elf_file() is False
    assert elf_analyzer._get_elf_symbols() == []
    assert elf_analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is False

    # Non-ELF path for direct hash calculation.
    pe_analyzer = TelfhashAnalyzer(adapter=None, filepath=str(pe_path))
    hash_value, method, error = pe_analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error
