from __future__ import annotations

from pathlib import Path

from r2inspect.abstractions.base_analyzer import BaseAnalyzer


class DemoAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return self._init_result_structure({"data": "ok"})

    def get_category(self) -> str:
        return "demo"

    def get_description(self) -> str:
        return "Demo analyzer"


def test_base_analyzer_helpers(tmp_path: Path) -> None:
    analyzer = DemoAnalyzer(filepath=tmp_path / "file.bin")
    assert analyzer.filepath == tmp_path / "file.bin"
    result = analyzer.analyze()
    assert result["available"] is False
    assert result["analyzer"] == "demo"
    assert analyzer.get_category() == "demo"
    assert analyzer.get_description() == "Demo analyzer"
    assert analyzer.get_name() == "demo"
    assert analyzer.supports_format("PE") is True
    assert "DemoAnalyzer" in repr(analyzer)
