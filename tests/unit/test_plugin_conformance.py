from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from r2inspect.abstractions import BaseAnalyzer
from r2inspect.application import plugin_conformance
from r2inspect.application.plugin_conformance import check_analyzer_class, load_plugin
from r2inspect.registry import AnalyzerCategory, AnalyzerSpec


class ConformingAnalyzer(BaseAnalyzer):
    spec = AnalyzerSpec(
        id="example.conforming",
        version="1.0.0",
        category=AnalyzerCategory.DETECTION,
        formats=frozenset({"PE"}),
        output_schema="example.conforming/v1",
    )

    def analyze(self) -> dict[str, object]:
        return {"available": True, "detected": False}


class LegacyAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return {"available": True}


def test_conforming_analyzer_passes_with_real_sample(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    result = check_analyzer_class(ConformingAnalyzer, sample=sample)

    assert result["status"] == "passed"
    assert {check["id"] for check in result["checks"]} == {
        "analyzer_class",
        "base_analyzer",
        "analyzer_spec",
        "construction",
        "sample_execution",
    }


def test_legacy_analyzer_fails_declarative_contract() -> None:
    result = check_analyzer_class(LegacyAnalyzer)

    assert result["status"] == "failed"
    assert (
        next(check for check in result["checks"] if check["id"] == "analyzer_spec")["status"]
        == "failed"
    )


def test_load_plugin_supports_module_class_and_registry_provider() -> None:
    assert load_plugin(f"{__name__}:ConformingAnalyzer")[0][1] is ConformingAnalyzer

    def provider(registry) -> None:
        registry.register(
            name="provider.analyzer",
            analyzer_class=ConformingAnalyzer,
            category=AnalyzerCategory.DETECTION,
        )

    class EntryPoint:
        def load(self):
            return provider

    class EntryPoints:
        def select(self, **_kwargs):
            return [EntryPoint()]

    loaded = load_plugin("provider", entry_points_fn=EntryPoints)
    assert loaded == [("provider.analyzer", ConformingAnalyzer)]


def test_plugin_conformance_reports_loader_and_runtime_failures(tmp_path: Path) -> None:
    class EntryPoints:
        def select(self, **_kwargs):
            return []

    with pytest.raises(ValueError, match="expected one"):
        load_plugin("missing", entry_points_fn=EntryPoints)

    class EmptyEntryPoint:
        def load(self):
            return lambda _registry: None

    class EmptyEntryPoints:
        def select(self, **_kwargs):
            return [EmptyEntryPoint()]

    with pytest.raises(ValueError, match="did not register"):
        load_plugin("empty", entry_points_fn=EmptyEntryPoints)
    with pytest.raises(TypeError, match="analyzer class or registry provider"):
        load_plugin(f"{__name__}:__annotations__")

    class BrokenAnalyzer(BaseAnalyzer):
        spec = ConformingAnalyzer.spec

        def __init__(self, *_args, **_kwargs) -> None:
            raise RuntimeError("construction failed")

        def analyze(self) -> dict[str, object]:
            return {}

    construction = check_analyzer_class(BrokenAnalyzer, sample=tmp_path / "sample.bin")
    assert (
        next(check for check in construction["checks"] if check["id"] == "construction")["status"]
        == "failed"
    )

    class InvalidOutputAnalyzer(ConformingAnalyzer):
        def analyze(self):
            return []

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    execution = check_analyzer_class(InvalidOutputAnalyzer, sample=sample)
    assert (
        next(check for check in execution["checks"] if check["id"] == "sample_execution")["status"]
        == "failed"
    )


def test_plugin_conformance_cli_reports_success_and_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["plugin-check", f"{__name__}:ConformingAnalyzer"])
    plugin_conformance.main()
    assert json.loads(capsys.readouterr().out)["status"] == "passed"

    monkeypatch.setattr(
        sys,
        "argv",
        ["plugin-check", f"{__name__}:ConformingAnalyzer", "--sample", str(tmp_path)],
    )
    with pytest.raises(SystemExit) as failed:
        plugin_conformance.main()
    assert failed.value.code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "failed"
