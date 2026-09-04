from __future__ import annotations

import struct
from pathlib import Path
from typing import Literal, Self

import pytest

from r2inspect.backends.consensus import ConsensusInspector, compare_results
from r2inspect.backends.core_backend import CoreBackendInspector
from r2inspect.backends.registry import available_backends
from r2inspect.interfaces import BinaryInspector


def test_core_backend_provides_independent_format_metadata(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF" + b"\0" * 8)
    result = CoreBackendInspector(str(sample), "elf-core").analyze()
    assert result["backend"] == "elf-core"
    assert result["format_detection"]["file_format"] == "ELF"
    assert result["file_info"]["sha256"]
    assert result["status"] == "failed"
    assert isinstance(CoreBackendInspector(str(sample), "elf-core"), BinaryInspector)


def test_elf_core_parses_real_structure() -> None:
    sample = Path("samples/fixtures/hello_elf")
    if not sample.exists():
        pytest.skip("hello_elf fixture missing")

    result = CoreBackendInspector(str(sample), "elf-core").analyze()

    assert "error" not in result
    assert result["file_info"]["architecture"] == "x86_64"
    assert result["file_info"]["bits"] == 64
    assert result["elf_info"]["entry_point"] == 0x125C
    assert len(result["sections"]) == 13
    assert len(result["elf_info"]["program_headers"]) == 8
    assert result["security"]["nx"] is True
    assert result["security"]["pie"] is True
    assert result["security"]["relro"] is True
    assert result["elf_info"]["overlay"]["size"] == 0


def test_pe_core_parses_real_structure() -> None:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("hello_pe.exe fixture missing")

    result = CoreBackendInspector(str(sample), "pe-core").analyze()

    assert "error" not in result
    assert result["file_info"]["architecture"] == "x86_64"
    assert result["pe_info"]["entry_point"] == 0x140001400
    assert len(result["sections"]) == 18
    assert any(item.get("name") == "Sleep" for item in result["imports"])
    assert result["security"]["aslr"] is True
    assert result["security"]["dep"] is True
    assert result["pe_info"]["overlay"]["size"] > 0
    assert result["pe_info"]["signature_status"] == "absent"


def test_pe_core_reports_truncated_structure(tmp_path: Path) -> None:
    sample = tmp_path / "truncated.exe"
    sample.write_bytes(b"MZ" + b"\0" * 62)

    result = CoreBackendInspector(str(sample), "pe-core").analyze()

    assert result["status"] == "failed"
    assert result["error"].startswith("invalid PE structure:")


def test_macho_core_parses_real_structure() -> None:
    sample = Path("samples/fixtures/hello_macho")
    if not sample.exists():
        pytest.skip("hello_macho fixture missing")

    result = CoreBackendInspector(str(sample), "macho-core").analyze()

    assert "error" not in result
    assert result["file_info"]["architecture"] == "arm64"
    assert result["file_info"]["bits"] == 64
    assert result["macho_info"]["entry_point"] == 0x100000460
    assert len(result["sections"]) == 5
    assert len(result["macho_info"]["segments"]) == 4
    assert "/usr/lib/libSystem.B.dylib" in result["macho_info"]["libraries"]
    assert any(item["name"] == "_puts" for item in result["imports"])
    assert any(item["name"] == "_main" for item in result["exports"])
    assert result["macho_info"]["uuid"] == "aa700f20-32f3-40f8-bc47-e22ab436ab16"
    assert result["security"]["pie"] is True
    assert result["security"]["nx"] is True
    assert result["macho_info"]["signature_status"] == "present"
    assert result["macho_info"]["overlay"]["size"] == 0


def test_macho_core_parses_fat_slice(tmp_path: Path) -> None:
    thin = Path("samples/fixtures/hello_macho")
    if not thin.exists():
        pytest.skip("hello_macho fixture missing")
    slice_offset = 4096
    thin_data = thin.read_bytes()
    header = struct.pack(">IIiiIII", 0xCAFEBABE, 1, 0x0100000C, 0, slice_offset, len(thin_data), 12)
    sample = tmp_path / "universal.macho"
    sample.write_bytes(header + bytes(slice_offset - len(header)) + thin_data)

    result = CoreBackendInspector(str(sample), "macho-core").analyze()

    assert "error" not in result
    assert result["macho_info"]["universal"] is True
    assert result["macho_info"]["architectures"] == ["arm64"]
    assert result["file_info"]["architecture"] == "arm64"


def test_consensus_marks_backend_disagreements() -> None:
    class FakeBackend:
        def __init__(self, value: str) -> None:
            self.value = value

        def analyze(self, **_options: object) -> dict[str, object]:
            return {"format_detection": {"file_format": self.value}}

        def close(self) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> Literal[False]:
            return False

    disagreement = compare_results(
        {"format_detection": {"file_format": "PE"}},
        {"format_detection": {"file_format": "ELF"}},
        "r2",
        "elf-core",
    )[0]
    assert disagreement == {
        "field": "format.common.format",
        "left_backend": "r2",
        "right_backend": "elf-core",
        "left": "PE",
        "right": "ELF",
        "severity": "warning",
        "status": "backend_disagreement",
    }
    result = ConsensusInspector(FakeBackend("PE"), FakeBackend("ELF"), "a", "b").analyze()
    assert result["backend"] == "consensus"
    assert result["backend_disagreements"]


def test_consensus_compares_structure_and_security() -> None:
    left = {
        "format_detection": {"file_format": "PE"},
        "pe_info": {
            "entry_point": 4096,
            "sections": [{"name": ".text", "vaddr": 4096, "size": 512}],
            "security_features": {"aslr": True},
        },
        "imports": [{"library": "kernel32.dll", "name": "Sleep"}],
    }
    right = {
        "format_detection": {"file_format": "PE"},
        "pe_info": {
            "entry_point": 8192,
            "sections": [{"name": ".text", "vaddr": 4096, "size": 1024}],
            "security_features": {"aslr": False},
        },
        "imports": [{"library": "kernel32.dll", "name": "Sleep"}],
    }

    fields = {item["field"] for item in compare_results(left, right)}

    assert fields == {
        "format.pe.entry_point",
        "format.pe.section_boundaries",
        "security.aslr",
    }


def test_consensus_normalizes_backend_specific_shapes() -> None:
    left = {
        "format_detection": {"file_format": "PE"},
        "file_info": {"architecture": "x86-64"},
        "sections": [{"name": ".text", "virtual_address": 4096, "virtual_size": 512}],
        "pe_info": {
            "overlay": {"overlay_offset": 8192, "overlay_size": 16, "has_overlay": True},
            "authenticode": {"has_signature": False},
            "security_features": {"aslr": True},
        },
    }
    right = {
        "format_detection": {"file_format": "PE"},
        "file_info": {"architecture": "x86_64"},
        "sections": [{"name": ".text", "vaddr": 4096, "size": 512}],
        "pe_info": {
            "overlay": {"offset": 8192, "size": 16},
            "signature_status": "absent",
            "security_features": {"aslr": True},
        },
    }

    assert compare_results(left, right) == []


def test_builtin_backends_are_discoverable() -> None:
    assert {"r2", "pe-core", "elf-core", "macho-core", "consensus"}.issubset(available_backends())
