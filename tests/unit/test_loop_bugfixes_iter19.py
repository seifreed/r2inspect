"""Regression test for loop iteration 19.

In parallel pipeline execution each stage runs on a deepcopy of the context and
only its returned results dict is merged back, so FormatDetectionStage's
``context["metadata"]["file_format"]`` mutation is discarded. The format,
hashing and security stages gated on ``metadata["file_format"]`` then saw
"Unknown" and were silently skipped. ``detected_file_format`` falls back to the
format the stage also returns under ``results["format_detection"]``.
"""

from __future__ import annotations

from r2inspect.pipeline.pipeline_runtime_common import detected_file_format


def test_metadata_path_used_when_present():
    ctx = {"metadata": {"file_format": "PE"}, "results": {}}
    assert detected_file_format(ctx) == "PE"


def test_falls_back_to_results_when_metadata_dropped():
    # Parallel mode: metadata mutation lost, but the detection stage's returned
    # dict was merged into results.
    ctx = {"metadata": {}, "results": {"format_detection": {"file_format": "ELF"}}}
    assert detected_file_format(ctx) == "ELF"


def test_default_when_format_unavailable():
    assert detected_file_format({"metadata": {}, "results": {}}) == "Unknown"
    assert detected_file_format({}) == "Unknown"


def test_metadata_takes_precedence_over_results():
    ctx = {
        "metadata": {"file_format": "PE"},
        "results": {"format_detection": {"file_format": "ELF"}},
    }
    assert detected_file_format(ctx) == "PE"
