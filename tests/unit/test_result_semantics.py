from __future__ import annotations

from r2inspect.application.options import build_analysis_options
from r2inspect.application.report_components import analyzer_outcomes
from r2inspect.application.result_semantics import normalize_analyzer_results
from r2inspect.application.technique_mappings import map_techniques
from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.abstractions.command_helper_mixin import CommandHelperMixin
from r2inspect.domain.results import TypedAnalyzerResult
from r2inspect.modules import yara_analyzer as yara_module
from r2inspect.modules.yara_analyzer import YaraAnalyzer


def test_failed_detection_is_not_reported_as_not_detected() -> None:
    results = {"detector": {"error": "backend timeout", "detected": False}}
    normalize_analyzer_results(results)
    assert results["detector"] == {
        "error": "backend timeout",
        "detected": None,
        "status": "timed_out",
    }


def test_clean_result_keeps_not_detected_state() -> None:
    results = {"detector": {"detected": False}}
    normalize_analyzer_results(results)
    assert results == {"detector": {"detected": False}}


def test_legacy_list_analyzer_error_is_exposed_as_outcome(tmp_path) -> None:
    class Config:
        def get_yara_rules_path(self) -> str:
            return str(tmp_path / "rules")

    original_yara = yara_module.yara
    yara_module.yara = None
    try:
        analyzer = YaraAnalyzer(None, config=Config(), filepath=str(tmp_path / "sample.bin"))
        assert analyzer.scan() == []
        outcomes = analyzer_outcomes(
            {
                "yara_matches": [],
                "_analyzer_status": {
                    "yara_analyzer": {
                        "status": analyzer.last_status,
                        "error": analyzer.last_error,
                    }
                },
            }
        )
    finally:
        yara_module.yara = original_yara
    assert outcomes[0].status.value == "dependency_unavailable"
    assert outcomes[0].error == "python-yara dependency unavailable"


def test_typed_analyzer_payload_is_exposed_as_outcome() -> None:
    payload = TypedAnalyzerResult({"finding_count": 0}, analyzer_id="typed_analyzer")

    outcomes = analyzer_outcomes({"typed_analyzer": payload})

    assert len(outcomes) == 1
    assert outcomes[0].analyzer_id == "typed_analyzer"
    assert outcomes[0].status.value == "completed"


def test_public_analyzer_entrypoints_return_typed_mapping_payloads() -> None:
    class BaseDemo(BaseAnalyzer):
        def analyze(self) -> dict[str, object]:
            return {"detected": True}

    class MixinDemo(CommandHelperMixin):
        def analyze(self) -> dict[str, object]:
            return {"detected": False}

    base_result = BaseDemo().analyze()
    mixin_result = MixinDemo().analyze()

    assert isinstance(base_result, TypedAnalyzerResult)
    assert isinstance(mixin_result, TypedAnalyzerResult)
    assert base_result["detected"] is True
    assert mixin_result["detected"] is False


def test_forensic_profile_enables_full_evidence() -> None:
    options = build_analysis_options(None, None, "forensic")
    assert options["deep_analysis"] is True
    assert options["forensic_evidence"] is True
    assert options["preserve_artifacts"] is True


def test_indicator_mapping_is_explicit() -> None:
    assert map_techniques("anti_analysis") == (["T1497", "T1622"], ["B0004"])
