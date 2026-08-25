from __future__ import annotations

from pathlib import Path

from r2inspect.backends.consensus import ConsensusInspector, compare_results
from r2inspect.backends.core_backend import CoreBackendInspector
from r2inspect.backends.registry import available_backends


def test_core_backend_provides_independent_format_metadata(tmp_path: Path) -> None:
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF" + b"\0" * 8)
    result = CoreBackendInspector(str(sample), "elf-core").analyze()
    assert result["backend"] == "elf-core"
    assert result["format_detection"]["file_format"] == "ELF"
    assert result["file_info"]["sha256"]


def test_consensus_marks_backend_disagreements() -> None:
    class FakeBackend:
        def __init__(self, value: str) -> None:
            self.value = value

        def analyze(self, **_options: object) -> dict[str, object]:
            return {"format_detection": {"file_format": self.value}}

    assert (
        compare_results(
            {"format_detection": {"file_format": "PE"}},
            {"format_detection": {"file_format": "ELF"}},
        )[0]["status"]
        == "backend_disagreement"
    )
    result = ConsensusInspector(FakeBackend("PE"), FakeBackend("ELF"), "a", "b").analyze()
    assert result["backend"] == "consensus"
    assert result["backend_disagreements"]


def test_builtin_backends_are_discoverable() -> None:
    assert {"r2", "pe-core", "elf-core", "macho-core", "consensus"}.issubset(available_backends())
