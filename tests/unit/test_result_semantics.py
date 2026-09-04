from __future__ import annotations

from r2inspect.application.options import build_analysis_options
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.application.report_components import analyzer_outcomes
from r2inspect.application.result_semantics import normalize_analyzer_results
from r2inspect.application.technique_mappings import map_techniques
from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.abstractions.command_helper_mixin import CommandHelperMixin
from r2inspect.domain.results import (
    AnalyzerError,
    AnalyzerExecution,
    AnalyzerStatus,
    TypedAnalyzerResult,
)
from r2inspect.modules import yara_analyzer as yara_module
from r2inspect.modules.yara_analyzer import YaraAnalyzer


def test_failed_detection_is_not_reported_as_not_detected() -> None:
    payload = {"error": "backend timeout", "detected": False}
    results = {
        "detector": payload,
        "_analyzer_executions": [
            AnalyzerExecution(
                analyzer_id="detector",
                status=AnalyzerStatus.TIMED_OUT,
                data=payload,
            )
        ],
    }
    normalize_analyzer_results(results)
    assert results["detector"] == {
        "error": "backend timeout",
        "detected": None,
        "status": "timed_out",
    }


def test_error_text_does_not_infer_analyzer_status() -> None:
    results = {"detector": {"error": "dependency timeout unsupported", "detected": False}}

    normalize_analyzer_results(results)

    assert results["detector"] == {
        "error": "dependency timeout unsupported",
        "detected": False,
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
        execution = AnalyzerExecution(
            analyzer_id="yara_analyzer",
            status=AnalyzerStatus(analyzer.last_status),
            data=[],
            errors=[
                AnalyzerError(
                    code="DEPENDENCY_UNAVAILABLE",
                    component="yara_analyzer",
                    message=str(analyzer.last_error),
                    recoverable=True,
                )
            ],
        )
        outcomes = analyzer_outcomes({"yara_matches": []}, [execution])
    finally:
        yara_module.yara = original_yara
    assert outcomes[0].status.value == "dependency_unavailable"
    assert outcomes[0].error == "python-yara dependency unavailable"


def test_list_payload_without_matches_has_analyzer_outcome() -> None:
    execution = AnalyzerExecution(
        analyzer_id="yara_analyzer",
        analyzer_version="1",
        output_schema="r2inspect.yara/v1",
        status=AnalyzerStatus.NOT_DETECTED,
        data=[],
    )

    outcomes = analyzer_outcomes({"yara_matches": []}, [execution])

    assert len(outcomes) == 1
    assert outcomes[0].analyzer_id == "yara_analyzer"
    assert outcomes[0].analyzer_version == "1"
    assert outcomes[0].output_schema == "r2inspect.yara/v1"
    assert outcomes[0].status is AnalyzerStatus.NOT_DETECTED


def test_analysis_result_keeps_execution_envelope_out_of_legacy_payload() -> None:
    execution = AnalyzerExecution(
        analyzer_id="yara_analyzer",
        status=AnalyzerStatus.NOT_DETECTED,
        data=[],
    )

    result = build_analysis_result({"yara_matches": [], "_analyzer_executions": [execution]})

    assert result.analyzer_executions == [execution]
    assert "_analyzer_executions" not in result.to_dict()


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

        def detect_compiler(self) -> dict[str, object]:
            return {"detected": True}

    base_result = BaseDemo().analyze()
    mixin_result = MixinDemo().analyze()

    assert isinstance(base_result, TypedAnalyzerResult)
    assert isinstance(mixin_result, TypedAnalyzerResult)
    assert base_result["detected"] is True
    assert mixin_result["detected"] is False
    assert isinstance(MixinDemo().detect_compiler(), TypedAnalyzerResult)


def test_forensic_profile_enables_full_evidence() -> None:
    options = build_analysis_options(None, None, "forensic")
    assert options["deep_analysis"] is True
    assert options["forensic_evidence"] is True
    assert options["preserve_artifacts"] is True


def test_indicator_mapping_is_explicit() -> None:
    assert map_techniques("anti_analysis") == (["T1497", "T1622"], ["B0004"])
