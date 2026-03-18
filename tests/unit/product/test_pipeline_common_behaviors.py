from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.helpers import make_stage_context

from r2inspect.pipeline.stages_common import AnalyzerStage, IndicatorStage


class MinimalAdapter:
    def get_imports(self) -> list[dict[str, str]]:
        return []

    def get_strings(self) -> list[str]:
        return []

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str) -> list[dict[str, str]]:
        return []


class AnalyzeAnalyzer:
    def __init__(self, **_kwargs) -> None:
        pass

    def analyze(self) -> dict[str, bool]:
        return {"ok": True}


class DetectAnalyzer:
    def __init__(self, **_kwargs) -> None:
        pass

    def detect(self) -> dict[str, bool]:
        return {"detected": True}


class BrokenAnalyzer:
    def __init__(self, **_kwargs) -> None:
        pass

    def analyze(self) -> dict[str, bool]:
        raise RuntimeError("broken")


def test_analyzer_stage_uses_available_analysis_method_and_stores_by_result_key() -> None:
    context = make_stage_context()
    stage = AnalyzerStage(
        name="detector",
        analyzer_class=DetectAnalyzer,
        adapter=MinimalAdapter(),
        config=None,
        filename="sample.bin",
        result_key="custom",
    )

    result = stage.execute(context)

    assert result["results"]["custom"]["detected"] is True
    assert context["results"]["custom"]["detected"] is True


def test_analyzer_stage_records_error_without_crashing_pipeline() -> None:
    context = make_stage_context()
    stage = AnalyzerStage(
        name="broken",
        analyzer_class=BrokenAnalyzer,
        adapter=MinimalAdapter(),
        config=None,
        filename="sample.bin",
    )

    result = stage.execute(context)

    assert "error" in result["results"]["broken"]
    assert "broken" in result["results"]["broken"]["error"]


def test_indicator_stage_generates_indicator_list_from_results() -> None:
    context = make_stage_context()
    context["results"] = {
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "SuspiciousRule"}],
    }
    stage = IndicatorStage()

    result = stage.execute(context)

    assert isinstance(result["indicators"], list)
    assert context["results"]["indicators"] == result["indicators"]
