from __future__ import annotations

from r2inspect.application.result_semantics import normalize_analyzer_results
from r2inspect.application.options import build_analysis_options
from r2inspect.application.technique_mappings import map_techniques


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


def test_forensic_profile_enables_full_evidence() -> None:
    options = build_analysis_options(None, None, "forensic")
    assert options["deep_analysis"] is True
    assert options["forensic_evidence"] is True
    assert options["preserve_artifacts"] is True


def test_indicator_mapping_is_explicit() -> None:
    assert map_techniques("anti_analysis") == (["T1497", "T1622"], ["B0004"])
