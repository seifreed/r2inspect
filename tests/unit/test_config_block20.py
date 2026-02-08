from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2inspect.config import Config


def test_config_alias_and_dict_access(tmp_path: Path):
    cfg = Config(str(tmp_path / "config.json"))
    assert isinstance(cfg.to_dict(), dict)

    cfg.apply_overrides({"custom": {"value": 123}})
    assert cfg.to_dict()["custom"]["value"] == 123
    assert "custom" in cfg.to_dict()
    assert isinstance(cfg.to_dict().get("custom"), dict)


def test_config_load_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    config_path = tmp_path / "bad.json"
    config_path.write_text("{")
    cfg = Config(str(config_path))
    out = capsys.readouterr().out
    assert "Warning: Could not load config" in out
    assert isinstance(cfg.to_dict(), dict)


def test_config_save_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cfg = Config(str(tmp_path / "config.json"))
    cfg.config_path = str(tmp_path)
    cfg.save_config()
    out = capsys.readouterr().out
    assert "Warning: Could not save config" in out


def test_config_load_from_dict_fallback(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cfg = Config(str(tmp_path / "config.json"))
    bad = {"general": {"min_string_length": 0}}
    cfg._load_from_dict(bad)
    out = capsys.readouterr().out
    assert "Invalid configuration values" in out
    assert cfg.typed_config.general.min_string_length == 4

    cfg._load_from_dict({"general": "oops"})
    out = capsys.readouterr().out
    assert "Invalid configuration values" in out


def test_config_misc_helpers(tmp_path: Path):
    cfg = Config(str(tmp_path / "config.json"))
    rules_path = cfg.get_yara_rules_path()
    assert rules_path.endswith("rules/yara")

    assert cfg.is_virustotal_enabled() is False
    assert cfg.get_virustotal_api_key() == ""

    clone = cfg.from_dict(cfg.to_dict())
    assert isinstance(clone, Config)
    assert clone.typed_config.general.max_strings == cfg.typed_config.general.max_strings
