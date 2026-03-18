from __future__ import annotations

from r2inspect.modules.resource_analyzer import run_resource_analysis


class _Logger:
    def error(self, _msg: str, *_args: object) -> None:
        return None

    def debug(self, _msg: str, *_args: object) -> None:
        return None


class _FailingAnalyzer:
    def _init_result_structure(self, _payload):
        raise RuntimeError("forced resource analysis failure")


def test_run_resource_analysis_handles_top_level_exception() -> None:
    result = run_resource_analysis(_FailingAnalyzer(), _Logger())
    assert result["available"] is False
    assert result["has_resources"] is False
    assert "forced resource analysis failure" in result["error"]
