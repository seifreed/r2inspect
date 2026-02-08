from __future__ import annotations

from pathlib import Path

from r2inspect.config import Config
from r2inspect.modules.yara_analyzer import YaraAnalyzer


def test_yara_analyzer_list_and_scan(tmp_path):
    config_path = tmp_path / "r2inspect.json"
    config = Config(config_path=str(config_path))

    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    analyzer = YaraAnalyzer(None, config, filepath=str(sample))

    rules_path = Path("r2inspect/rules/yara")
    assert rules_path.exists()
    available = analyzer.list_available_rules(str(rules_path))
    assert isinstance(available, list)
    assert available
    assert {"name", "path", "size", "modified", "type"}.issubset(available[0].keys())

    matches = analyzer.scan(custom_rules_path=str(rules_path))
    assert isinstance(matches, list)
