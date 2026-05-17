from __future__ import annotations

from pathlib import Path
from typing import Any
import subprocess
import textwrap

import pytest

from r2inspect.infrastructure.ssdeep_loader import get_ssdeep
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from tests.helpers import FakeR2Adapter


class ImportAdapter(FakeR2Adapter):
    def __init__(self) -> None:
        super().__init__(
            cmdj_responses={
                "iij": [
                    {"libname": "KERNEL32.dll", "name": "CreateFileA"},
                    {"library": "USER32.dll", "name": "MessageBoxA"},
                ]
            }
        )

    def get_imports(self) -> list[dict[str, str]]:
        return [
            {"libname": "KERNEL32.dll", "name": "CreateFileA"},
            {"library": "USER32.dll", "name": "MessageBoxA"},
        ]


class ElfAdapter:
    def __init__(self, *, symbols: Any, info: dict[str, Any] | None = None) -> None:
        self.symbols = symbols
        self.info = info or {"bin": {"os": "linux", "format": "elf"}}

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "isj":
            return self.symbols
        if command == "ij":
            return self.info
        return default


class RaisingElfAdapter(ElfAdapter):
    def __init__(self, *, info: dict[str, Any] | None = None) -> None:
        super().__init__(symbols=[], info=info)

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "isj":
            raise RuntimeError("symbols unavailable")
        return super().cmdj(command, default)


class ForcePEImpfuzzyAnalyzer(ImpfuzzyAnalyzer):
    def _is_pe_file(self) -> bool:
        return True


class OSErrorPath:
    def __str__(self) -> str:
        return "samples/fixtures/hello_pe.exe"

    def __fspath__(self) -> str:
        raise OSError("simulated read error")


class TypeErrorPath:
    def __str__(self) -> str:
        return "samples/fixtures/hello_pe.exe"


class ExplodingStrPath:
    def __str__(self) -> str:
        raise RuntimeError("stringify failed")


class ForceELFTelfhashAnalyzer(TelfhashAnalyzer):
    def _is_elf_file(self) -> bool:
        return True


class RaisingCmdListTelfhashAnalyzer(TelfhashAnalyzer):
    def _cmd_list(self, command: str) -> list[dict[str, Any]]:
        raise RuntimeError(f"{command} unavailable")


def build_telfhashable_elf(tmp_path: Path) -> Path:
    source = tmp_path / "telfhash_sample.c"
    obj = tmp_path / "telfhash_sample.o"
    shared = tmp_path / "telfhash_sample.so"
    source.write_text(textwrap.dedent("""
            int exported(void) { return 1; }
            int main(void) { return exported(); }
            """))
    subprocess.run(
        ["clang", "--target=x86_64-linux-gnu", "-fPIC", "-c", str(source), "-o", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["ld.lld", "-shared", "-m", "elf_x86_64", str(obj), "-o", str(shared)],
        check=True,
        capture_output=True,
        text=True,
    )
    return shared


def test_ssdeep_analyzer_real_library_and_compare() -> None:
    if get_ssdeep() is None:
        pytest.skip("ssdeep Python library not installed")
    sample = "samples/fixtures/hello_pe.exe"
    analyzer = SSDeepAnalyzer(sample)

    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None

    hash_value, method_used, error = analyzer._calculate_hash()
    assert hash_value
    assert method_used == "python_library"
    assert error is None

    assert analyzer._get_hash_type() == "ssdeep"
    assert SSDeepAnalyzer.compare_hashes(hash_value, hash_value) == 100
    assert SSDeepAnalyzer.is_available() is True


def test_ssdeep_analyzer_real_library_fallback_paths() -> None:
    if get_ssdeep() is None:
        pytest.skip("ssdeep Python library not installed")
    oserr_analyzer = SSDeepAnalyzer("samples/fixtures/hello_pe.exe")
    oserr_analyzer.filepath = OSErrorPath()
    hash_value, method_used, error = oserr_analyzer._calculate_hash()
    assert hash_value
    assert method_used == "python_library"
    assert error is None

    typeerr_analyzer = SSDeepAnalyzer("samples/fixtures/hello_pe.exe")
    typeerr_analyzer.filepath = TypeErrorPath()
    hash_value, method_used, error = typeerr_analyzer._calculate_hash()
    assert hash_value is None
    assert method_used is None
    assert error is not None

    assert SSDeepAnalyzer.compare_hashes("3:abcd:abcd", "not-a-hash") is None


def test_ssdeep_analyzer_library_absent_branch() -> None:
    analyzer = SSDeepAnalyzer("samples/fixtures/hello_pe.exe")
    hash_value, method_used, error = analyzer._calculate_hash(get_ssdeep_fn=lambda: None)
    assert hash_value is None
    assert method_used is None
    assert error is not None
    assert "not available" in error.lower()
    assert SSDeepAnalyzer.compare_hashes("", "") is None


def test_ssdeep_analyzer_missing_file_and_library_error_paths(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    analyzer = SSDeepAnalyzer(str(missing))
    hash_value, method_used, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method_used is None
    assert error is not None

    class _RaisingModule:
        def hash(self, data: bytes) -> str:
            raise RuntimeError("hash boom")

        def hash_from_file(self, path: str) -> str:
            raise RuntimeError("hash_from_file boom")

    present = tmp_path / "present.bin"
    present.write_bytes(b"A" * 256)
    present_analyzer = SSDeepAnalyzer(str(present))
    hv, mu, err = present_analyzer._calculate_hash(get_ssdeep_fn=lambda: _RaisingModule())
    assert hv is None
    assert mu is None
    assert err is not None
    assert "library error" in err.lower()


def test_impfuzzy_analyzer_real_hash_and_import_processing() -> None:
    sample = "samples/fixtures/hello_pe.exe"
    analyzer = ImpfuzzyAnalyzer(ImportAdapter(), sample)

    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None
    assert analyzer._is_pe_file() is True

    hash_value, method_used, error = analyzer._calculate_hash()
    assert hash_value
    assert method_used == "python_library"
    assert error is None

    details = analyzer.analyze_imports()
    assert details["library_available"] is True
    assert details["import_count"] >= 2
    assert details["dll_count"] >= 2
    assert "kernel32.createfilea" in details["imports_processed"]

    processed = analyzer._process_imports(analyzer._extract_imports())
    assert processed == sorted(processed)
    assert ImpfuzzyAnalyzer.calculate_impfuzzy_from_file(sample)
    assert ImpfuzzyAnalyzer.compare_hashes(hash_value, hash_value) == 100
    assert analyzer._get_hash_type() == "impfuzzy"


def test_impfuzzy_analyzer_non_pe_and_error_paths_real(tmp_path: Path) -> None:
    not_pe = ImpfuzzyAnalyzer(ImportAdapter(), "samples/fixtures/hello_elf")
    assert not_pe._calculate_hash() == (None, None, "File is not a PE binary")
    assert not_pe._get_hash_type() == "impfuzzy"

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"abc")
    forced = ForcePEImpfuzzyAnalyzer(ImportAdapter(), str(tiny))
    hash_value, method_used, error = forced._calculate_hash()
    assert hash_value is None
    assert method_used is None
    assert error is not None

    fallback = ImpfuzzyAnalyzer(
        FakeR2Adapter(
            cmdj_responses={"iij": [], "ii": {"libname": "ADVAPI32.dll", "name": "CryptEncrypt"}}
        ),
        "samples/fixtures/hello_pe.exe",
    )
    assert fallback._extract_imports() == [{"libname": "ADVAPI32.dll", "name": "CryptEncrypt"}]


def test_telfhash_analyzer_real_paths_and_symbol_helpers() -> None:
    sample = "samples/fixtures/hello_elf"
    analyzer = TelfhashAnalyzer(
        ElfAdapter(
            symbols=[
                {"type": "FUNC", "bind": "GLOBAL", "name": "main"},
                {"type": "OBJECT", "bind": "WEAK", "name": "obj1"},
                {"type": "FUNC", "bind": "LOCAL", "name": "skip_local"},
            ]
        ),
        filepath=sample,
    )

    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None
    assert analyzer._is_elf_file() is True
    assert analyzer._has_elf_symbols({"bin": {"os": "linux"}}) is True

    symbols = analyzer._get_elf_symbols()
    assert len(symbols) == 3
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(filtered) == 2
    assert analyzer._extract_symbol_names(filtered) == ["main", "obj1"]

    hash_value, method_used, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method_used is None
    assert error is not None

    details = analyzer.analyze_symbols()
    assert details["available"] is True
    assert details["is_elf"] is True
    assert details["symbol_count"] == 3
    assert details["filtered_symbols"] == 2
    assert analyzer._get_hash_type() == "telfhash"
    assert analyzer.analyze()["telfhash"] == analyzer.analyze()["hash_value"]
    assert TelfhashAnalyzer.calculate_telfhash_from_file(sample) is None
    assert TelfhashAnalyzer.compare_hashes("", "") is None
    assert TelfhashAnalyzer.calculate_telfhash_from_file("no_such_file") is None


def test_telfhash_analyzer_real_success_and_exception_paths(tmp_path: Path) -> None:
    elf_path = build_telfhashable_elf(tmp_path)
    analyzer = TelfhashAnalyzer(
        ElfAdapter(
            symbols=[
                {"type": "FUNC", "bind": "GLOBAL", "name": "exported"},
                {"type": "FUNC", "bind": "GLOBAL", "name": "main"},
            ]
        ),
        filepath=str(elf_path),
    )

    hash_value, method_used, error = analyzer._calculate_hash()
    assert hash_value == "tnull"
    assert method_used == "python_library"
    assert error is None
    assert analyzer.analyze()["telfhash"] == "tnull"
    assert TelfhashAnalyzer.calculate_telfhash_from_file(str(elf_path)) == "tnull"

    nohash_analyzer = TelfhashAnalyzer(
        ElfAdapter(symbols=[{"type": "FUNC", "bind": "GLOBAL", "name": "main"}]),
        filepath="/opt/homebrew/bin/python3",
    )
    assert nohash_analyzer._calculate_hash() == (
        None,
        None,
        "Telfhash calculation returned no hash",
    )
    assert TelfhashAnalyzer.compare_hashes("tnull", "not-a-hash") is None

    exploding = ForceELFTelfhashAnalyzer(
        ElfAdapter(symbols=[{"type": "FUNC", "bind": "GLOBAL", "name": "main"}]),
        filepath="samples/fixtures/hello_elf",
    )
    exploding.filepath = ExplodingStrPath()
    hash_value, method_used, error = exploding._calculate_hash()
    assert hash_value is None
    assert method_used is None
    assert error is not None

    assert TelfhashAnalyzer.calculate_telfhash_from_file(Path(elf_path)) is None


def test_telfhash_analyzer_non_elf_and_symbol_error_paths() -> None:
    pe_sample = "samples/fixtures/hello_pe.exe"
    analyzer = TelfhashAnalyzer(
        ElfAdapter(symbols=[], info={"bin": {"os": "windows", "format": "pe"}}), filepath=pe_sample
    )
    assert analyzer._is_elf_file() is False
    assert analyzer._has_elf_symbols(None) is False
    assert analyzer.analyze_symbols()["error"] == "File is not an ELF binary"
    assert analyzer._calculate_hash() == (None, None, "File is not an ELF binary")

    broken = TelfhashAnalyzer(
        RaisingElfAdapter(info={"bin": {"os": "linux", "format": "elf"}}),
        filepath="samples/fixtures/hello_elf",
    )
    assert broken._get_elf_symbols() == []
    assert broken._has_elf_symbols({"bin": {"os": "linux"}}) is False

    broken_cmd_list = RaisingCmdListTelfhashAnalyzer(
        ElfAdapter(symbols=[], info={"bin": {"os": "linux", "format": "elf"}}),
        filepath="samples/fixtures/hello_elf",
    )
    assert broken_cmd_list._has_elf_symbols({"bin": {"os": "linux"}}) is False
    assert broken_cmd_list._get_elf_symbols() == []
