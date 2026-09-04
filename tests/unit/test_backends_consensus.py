from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

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
    assert isinstance(CoreBackendInspector(str(sample), "elf-core"), BinaryInspector)


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


def test_builtin_backends_are_discoverable() -> None:
    assert {"r2", "pe-core", "elf-core", "macho-core", "consensus"}.issubset(available_backends())
