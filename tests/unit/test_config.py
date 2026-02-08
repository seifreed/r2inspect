from pathlib import Path

from r2inspect.config import Config


def test_config_creates_default_file(tmp_path):
    config_path = tmp_path / "config.json"
    config = Config(str(config_path))

    assert config_path.exists()
    assert config.typed_config.general.max_strings == 1000


def test_config_loads_and_merges_user_config(tmp_path):
    config_path = tmp_path / "config.json"
    config = Config(str(config_path))

    config_path.write_text('{"general": {"max_strings": 42}, "custom": {"x": 1}}')
    config.load_config()

    assert config.typed_config.general.max_strings == 42
    assert config.to_dict()["custom"]["x"] == 1


def test_config_apply_overrides_updates_typed_config(tmp_path):
    config_path = tmp_path / "config.json"
    config = Config(str(config_path))

    config.apply_overrides({"pipeline": {"max_workers": 8, "parallel_execution": True}})

    assert config.typed_config.pipeline.max_workers == 8
    assert config.typed_config.pipeline.parallel_execution is True


def test_config_load_invalid_values_fallbacks(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text('{"general": {"min_string_length": 0}}')

    config = Config(str(config_path))
    # Invalid config should fall back to default values
    assert config.typed_config.general.min_string_length == 4


def test_get_yara_rules_path_is_absolute(tmp_path):
    config = Config(str(tmp_path / "config.json"))
    rules_path = config.get_yara_rules_path()
    assert Path(rules_path).is_absolute()
    assert rules_path.endswith("rules/yara")


def test_virustotal_enabled_flag(tmp_path):
    config = Config(str(tmp_path / "config.json"))
    cfg2 = config.from_dict({"virustotal": {"api_key": "key", "enabled": True}})
    assert cfg2.is_virustotal_enabled() is True
    assert cfg2.get_virustotal_api_key() == "key"
