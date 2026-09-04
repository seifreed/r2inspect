from __future__ import annotations

from pathlib import Path

from r2inspect.abstractions import BaseAnalyzer
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
