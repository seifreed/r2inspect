"""Branch-path tests for r2inspect/config.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2inspect.config import Config


# ---------------------------------------------------------------------------
# Config.__init__ - new file creates default (line 90)
# ---------------------------------------------------------------------------


def test_config_creates_default_config_when_file_missing(tmp_path: Path):
    config_path = tmp_path / "new_config.json"
    assert not config_path.exists()
    cfg = Config(str(config_path))
    assert config_path.exists()
    assert isinstance(cfg.to_dict(), dict)


def test_config_loads_existing_file(tmp_path: Path):
    config_path = tmp_path / "existing.json"
    data = dict(Config.DEFAULT_CONFIG)
    data["general"] = dict(data["general"])
    data["general"]["max_strings"] = 555
    config_path.write_text(json.dumps(data))
    cfg = Config(str(config_path))
    assert cfg.typed_config.general.max_strings == 555


# ---------------------------------------------------------------------------
# _merge_config - new section not in defaults (lines 124, 126)
# ---------------------------------------------------------------------------


def test_merge_config_adds_new_section():
    merged = Config._merge_config(
        {"general": {"verbose": False}},
        {"custom_section": {"key": "value"}},
    )
    assert merged["custom_section"]["key"] == "value"
    assert merged["general"]["verbose"] is False


def test_merge_config_overwrites_non_dict_section():
    merged = Config._merge_config(
        {"flag": True},
        {"flag": False},
    )
    assert merged["flag"] is False


def test_merge_config_merges_dict_section():
    merged = Config._merge_config(
        {"general": {"verbose": False, "max_strings": 1000}},
        {"general": {"verbose": True}},
    )
    assert merged["general"]["verbose"] is True
    assert merged["general"]["max_strings"] == 1000


# ---------------------------------------------------------------------------
# _load_from_dict - ValueError / TypeError fallback (lines 145-148)
# ---------------------------------------------------------------------------


def test_load_from_dict_falls_back_to_defaults_on_invalid_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    cfg = Config(str(tmp_path / "cfg.json"))
    # min_string_length=0 triggers ValueError in GeneralConfig.__post_init__
    cfg._load_from_dict({"general": {"min_string_length": 0}})
    out = capsys.readouterr().out
    assert "Invalid configuration values" in out
    assert cfg.typed_config.general.min_string_length == 4


def test_load_from_dict_falls_back_to_defaults_on_type_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    cfg = Config(str(tmp_path / "cfg.json"))
    # Passing a non-dict for 'general' triggers a TypeError or ValueError
    cfg._load_from_dict({"general": "not_a_dict"})
    out = capsys.readouterr().out
    assert "Invalid configuration values" in out


# ---------------------------------------------------------------------------
# save_config (line 152)
# ---------------------------------------------------------------------------


def test_save_config_writes_json_file(tmp_path: Path):
    config_path = tmp_path / "save_test.json"
    cfg = Config(str(config_path))
    config_path.unlink()
    cfg.save_config()
    assert config_path.exists()
    loaded = json.loads(config_path.read_text())
    assert "general" in loaded


# ---------------------------------------------------------------------------
# apply_overrides - non-dict setting (line 166)
# ---------------------------------------------------------------------------


def test_apply_overrides_with_non_dict_value_replaces_section(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.apply_overrides({"general": "replaced_with_string"})
    assert cfg.to_dict()["general"] == "replaced_with_string"


def test_apply_overrides_with_dict_value_merges(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.apply_overrides({"general": {"verbose": True}})
    assert cfg.to_dict()["general"]["verbose"] is True


def test_apply_overrides_adds_new_section(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.apply_overrides({"new_section": {"data": 42}})
    assert cfg.to_dict()["new_section"]["data"] == 42


# ---------------------------------------------------------------------------
# set method (lines 178-184)
# ---------------------------------------------------------------------------


def test_set_creates_new_section_when_missing(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.set("nonexistent_section", "my_key", "my_value")
    assert cfg.to_dict()["nonexistent_section"]["my_key"] == "my_value"


def test_set_updates_existing_key(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.set("output", "json_indent", 4)
    assert cfg.to_dict()["output"]["json_indent"] == 4


def test_set_creates_key_in_existing_section(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.set("general", "new_key", 999)
    assert cfg.to_dict()["general"]["new_key"] == 999


# ---------------------------------------------------------------------------
# from_dict (lines 196-199)
# ---------------------------------------------------------------------------


def test_from_dict_returns_new_config_instance(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    d = cfg.to_dict()
    clone = cfg.from_dict(d)
    assert isinstance(clone, Config)
    assert clone.typed_config.general.max_strings == cfg.typed_config.general.max_strings


def test_from_dict_uses_same_config_path(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    clone = cfg.from_dict(cfg.to_dict())
    assert clone.config_path == cfg.config_path


# ---------------------------------------------------------------------------
# get_yara_rules_path - absolute vs relative (lines 221, 225)
# ---------------------------------------------------------------------------


def test_get_yara_rules_path_returns_string(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    path = cfg.get_yara_rules_path()
    assert isinstance(path, str)
    assert "rules/yara" in path or path.startswith("/")


def test_get_yara_rules_path_absolute_path_used_as_is(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    abs_path = str(tmp_path / "my_yara_rules")
    cfg.set("yara", "rules_path", abs_path)
    result = cfg.get_yara_rules_path()
    assert result == abs_path


def test_get_yara_rules_path_relative_path_joined_with_package(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    cfg.set("yara", "rules_path", "rules/yara")
    result = cfg.get_yara_rules_path()
    assert result.endswith("rules/yara")
    assert Path(result).is_absolute()


# ---------------------------------------------------------------------------
# Property accessors (lines 231, 236, 241, 246)
# ---------------------------------------------------------------------------


def test_analyze_authenticode_property(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    assert isinstance(cfg.analyze_authenticode, bool)
    assert cfg.analyze_authenticode is True


def test_analyze_overlay_property(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    assert isinstance(cfg.analyze_overlay, bool)
    assert cfg.analyze_overlay is True


def test_analyze_resources_property(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    assert isinstance(cfg.analyze_resources, bool)
    assert cfg.analyze_resources is True


def test_analyze_mitigations_property(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    assert isinstance(cfg.analyze_mitigations, bool)
    assert cfg.analyze_mitigations is True


def test_is_virustotal_enabled_returns_false_by_default(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    assert cfg.is_virustotal_enabled() is False


def test_get_virustotal_api_key_returns_empty_string_by_default(tmp_path: Path):
    cfg = Config(str(tmp_path / "cfg.json"))
    assert cfg.get_virustotal_api_key() == ""
