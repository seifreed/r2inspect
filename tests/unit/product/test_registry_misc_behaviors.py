from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import r2inspect.infrastructure.file_type as file_type_mod
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer
from r2inspect.pipeline.stage_models import AnalysisStage
from r2inspect.pipeline.stages_format import FileInfoStage, _resolved_path
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory


class FakeAnalyzer:
    pass


class FakeStage(AnalysisStage):
    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(name=name, description="stage", optional=False, **kwargs)

    def _execute(self, _context: dict[str, object]) -> dict[str, object]:
        return {self.name: {"ok": True}}


class AuthAdapter:
    def __init__(self, responses: dict[str, Any] | None = None):
        self.responses = responses or {}

    def cmdj(self, cmd: str):
        return self.responses.get(cmd)

    def cmd(self, _cmd: str) -> str:
        return ""


class Adapter:
    def cmdj(self, _cmd: str):
        return {}

    def cmd(self, _cmd: str):
        return ""


class FileInfoAdapter:
    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "format": "pe"}}


def test_registry_filters_required_optional_and_detects_cycles() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="base",
        analyzer_class=FakeAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        required=True,
    )
    registry.register(
        name="child",
        analyzer_class=FakeAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        required=False,
        dependencies={"base"},
    )

    assert "base" in registry.get_required_analyzers()
    assert "child" in registry.get_optional_analyzers()
    assert registry.get_dependencies("missing") == set()
    assert registry.resolve_execution_order(["child", "base"]) == ["base", "child"]

    cyclic = AnalyzerRegistry(lazy_loading=False)
    cyclic.register(
        name="a",
        analyzer_class=FakeAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        dependencies={"b"},
    )
    cyclic.register(
        name="b",
        analyzer_class=FakeAnalyzer,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        dependencies={"a"},
    )
    with pytest.raises(ValueError):
        cyclic.resolve_execution_order(["a", "b"])


def test_authenticode_and_hashing_helpers_expose_consistent_behavior() -> None:
    analyzer = AuthenticodeAnalyzer(
        AuthAdapter({"iDj": [{"name": "SECURITY", "paddr": 1, "vaddr": 2, "size": 3}]})
    )
    assert analyzer._get_security_directory() == {
        "name": "SECURITY",
        "paddr": 1,
        "vaddr": 2,
        "size": 3,
    }
    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": [1],
                "errors": [],
                "security_directory": {"size": 10},
            }
        )
        is True
    )
    assert analyzer._verify_signature_integrity({"has_signature": False}) is False

    simhash = SimHashAnalyzer(adapter=Adapter(), filepath="/tmp/f.bin")
    extracted = simhash._extract_opcodes_from_ops([{"opcode": "mov eax, ebx"}, {"mnemonic": "ret"}])
    assert "OP:mov" in extracted
    simhash.analyze = lambda: {"available": True, "hash_value": 12345}  # type: ignore[method-assign]
    assert "distance" in simhash.calculate_similarity(54321, hash_type="combined")

    tlsh = TLSHAnalyzer(adapter=Adapter(), filename="/tmp/f.bin")
    tlsh._get_sections = lambda: [{"name": ".text", "vaddr": 4096, "size": 16}]  # type: ignore[method-assign]
    tlsh._read_bytes_hex = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("read"))  # type: ignore[method-assign]
    assert tlsh._calculate_section_tlsh()[".text"] is None


def test_file_type_and_stage_support_fall_back_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"\x00" * 32)

    monkeypatch.setattr(Path, "resolve", lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _resolved_path("abc.bin") == "abc.bin"

    monkeypatch.setattr(
        "r2inspect.infrastructure.file_type.cmdj_helper",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("ij-fail")),
    )
    silent_logger = SimpleNamespace(debug=lambda *_a, **_k: None, error=lambda *_a, **_k: None)
    assert (
        file_type_mod.is_pe_file(
            "x", SimpleNamespace(get_info_text=lambda: ""), None, logger=silent_logger
        )
        is False
    )

    monkeypatch.setattr("r2inspect.pipeline.stages_format._get_magic_detectors", lambda: None)
    stage = FileInfoStage(adapter=FileInfoAdapter(), filename=str(sample))
    result = stage._execute({"results": {}})
    assert result["file_info"]["architecture"] == "x86"
    assert result["file_info"]["mime_type"] is None
