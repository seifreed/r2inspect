from __future__ import annotations

from r2inspect.pipeline.stages_common import AnalyzerStage, IndicatorStage


class _FakeAdapter:
    def get_imports(self) -> list:
        return []

    def get_strings(self) -> list:
        return []

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str) -> list:
        return []


def test_analyzer_stage_result_key_defaults_to_name() -> None:
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            pass

        def analyze(self) -> dict:
            return {"ok": True}

    stage = AnalyzerStage(
        name="my_analyzer",
        analyzer_class=Analyzer,
        adapter=_FakeAdapter(),
        config=None,
        filename="test.bin",
    )
    context = {"results": {}}
    result = stage.execute(context)
    assert "my_analyzer" in result["results"]


def test_analyzer_stage_custom_result_key() -> None:
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            pass

        def analyze(self) -> dict:
            return {"data": "x"}

    stage = AnalyzerStage(
        name="my_analyzer",
        analyzer_class=Analyzer,
        adapter=_FakeAdapter(),
        config=None,
        filename="test.bin",
        result_key="custom_key",
    )
    context = {"results": {}}
    result = stage.execute(context)
    assert "custom_key" in result["results"]
    assert result["results"]["custom_key"]["data"] == "x"


def test_analyzer_stage_uses_detect_method() -> None:
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            pass

        def detect(self) -> dict:
            return {"detected": True}

    stage = AnalyzerStage(
        name="detector",
        analyzer_class=Analyzer,
        adapter=_FakeAdapter(),
        config=None,
        filename="test.bin",
    )
    context = {"results": {}}
    result = stage.execute(context)
    assert result["results"]["detector"]["detected"] is True


def test_analyzer_stage_uses_scan_method() -> None:
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            pass

        def scan(self) -> dict:
            return {"scanned": True}

    stage = AnalyzerStage(
        name="scanner",
        analyzer_class=Analyzer,
        adapter=_FakeAdapter(),
        config=None,
        filename="test.bin",
    )
    context = {"results": {}}
    result = stage.execute(context)
    assert result["results"]["scanner"]["scanned"] is True


def test_analyzer_stage_error_stored_in_result() -> None:
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            pass

        def analyze(self) -> dict:
            raise RuntimeError("analysis failed")

    stage = AnalyzerStage(
        name="bad_analyzer",
        analyzer_class=Analyzer,
        adapter=_FakeAdapter(),
        config=None,
        filename="test.bin",
    )
    context = {"results": {}}
    result = stage.execute(context)
    assert "error" in result["results"]["bad_analyzer"]
    assert "analysis failed" in result["results"]["bad_analyzer"]["error"]


def test_analyzer_stage_optional_false() -> None:
    class Analyzer:
        def __init__(self, adapter=None, config=None, filename=None) -> None:
            pass

        def analyze(self) -> dict:
            return {}

    stage = AnalyzerStage(
        name="required",
        analyzer_class=Analyzer,
        adapter=_FakeAdapter(),
        config=None,
        filename="test.bin",
        optional=False,
    )
    assert stage.optional is False


def test_indicator_stage_name_and_description() -> None:
    stage = IndicatorStage()
    assert stage.name == "indicators"
    assert "indicators" in stage.description.lower()


def test_indicator_stage_executes_with_empty_results() -> None:
    stage = IndicatorStage()
    context = {"results": {}}
    result = stage.execute(context)
    assert "indicators" in result


def test_indicator_stage_returns_indicators_key() -> None:
    stage = IndicatorStage()
    context = {
        "results": {
            "packer": {"is_packed": True, "packer_type": "UPX"},
            "anti_analysis": {"anti_debug": True, "anti_vm": False},
        }
    }
    result = stage.execute(context)
    assert "indicators" in result
    assert isinstance(result["indicators"], list)
