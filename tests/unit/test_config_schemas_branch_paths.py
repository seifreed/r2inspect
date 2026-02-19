from __future__ import annotations

import pytest

from r2inspect.config_schemas.schemas import (
    AnalysisConfig,
    GeneralConfig,
    OutputConfig,
    PackerConfig,
    PEAnalysisConfig,
    PipelineConfig,
    R2InspectConfig,
    StringsConfig,
    VirusTotalConfig,
    YaraConfig,
)
from r2inspect.config_store import ConfigStore


# ----- GeneralConfig validation -----

def test_general_config_negative_max_strings_raises() -> None:
    with pytest.raises(ValueError, match="max_strings"):
        GeneralConfig(max_strings=-1)


def test_general_config_zero_min_string_length_raises() -> None:
    with pytest.raises(ValueError, match="min_string_length"):
        GeneralConfig(min_string_length=0)


def test_general_config_max_less_than_min_string_raises() -> None:
    with pytest.raises(ValueError, match="max_string_length"):
        GeneralConfig(min_string_length=10, max_string_length=5)


def test_general_config_defaults_valid() -> None:
    cfg = GeneralConfig()
    assert cfg.max_strings == 1000
    assert cfg.min_string_length == 4


# ----- YaraConfig validation -----

def test_yara_config_zero_timeout_raises() -> None:
    with pytest.raises(ValueError, match="timeout"):
        YaraConfig(timeout=0)


def test_yara_config_negative_timeout_raises() -> None:
    with pytest.raises(ValueError, match="timeout"):
        YaraConfig(timeout=-5)


def test_yara_config_valid() -> None:
    cfg = YaraConfig(timeout=30)
    assert cfg.timeout == 30


# ----- PackerConfig validation -----

def test_packer_config_entropy_below_zero_raises() -> None:
    with pytest.raises(ValueError, match="entropy_threshold"):
        PackerConfig(entropy_threshold=-0.1)


def test_packer_config_entropy_above_eight_raises() -> None:
    with pytest.raises(ValueError, match="entropy_threshold"):
        PackerConfig(entropy_threshold=8.1)


def test_packer_config_valid_boundary() -> None:
    cfg = PackerConfig(entropy_threshold=0.0)
    assert cfg.entropy_threshold == 0.0
    cfg2 = PackerConfig(entropy_threshold=8.0)
    assert cfg2.entropy_threshold == 8.0


# ----- StringsConfig validation -----

def test_strings_config_zero_min_length_raises() -> None:
    with pytest.raises(ValueError, match="min_length"):
        StringsConfig(min_length=0)


def test_strings_config_max_less_than_min_raises() -> None:
    with pytest.raises(ValueError, match="max_length"):
        StringsConfig(min_length=10, max_length=5)


def test_strings_config_valid() -> None:
    cfg = StringsConfig(min_length=4, max_length=200)
    assert cfg.min_length == 4


# ----- OutputConfig validation -----

def test_output_config_negative_indent_raises() -> None:
    with pytest.raises(ValueError, match="json_indent"):
        OutputConfig(json_indent=-1)


def test_output_config_multi_char_delimiter_raises() -> None:
    with pytest.raises(ValueError, match="csv_delimiter"):
        OutputConfig(csv_delimiter=",,")


def test_output_config_empty_delimiter_raises() -> None:
    with pytest.raises(ValueError, match="csv_delimiter"):
        OutputConfig(csv_delimiter="")


def test_output_config_valid() -> None:
    cfg = OutputConfig(json_indent=4, csv_delimiter=";")
    assert cfg.json_indent == 4
    assert cfg.csv_delimiter == ";"


# ----- VirusTotalConfig validation -----

def test_virustotal_config_zero_timeout_raises() -> None:
    with pytest.raises(ValueError, match="timeout"):
        VirusTotalConfig(timeout=0)


def test_virustotal_config_is_configured_false_when_disabled() -> None:
    cfg = VirusTotalConfig(enabled=False, api_key="key123")
    assert cfg.is_configured is False


def test_virustotal_config_is_configured_false_when_no_key() -> None:
    cfg = VirusTotalConfig(enabled=True, api_key="")
    assert cfg.is_configured is False


def test_virustotal_config_is_configured_true() -> None:
    cfg = VirusTotalConfig(enabled=True, api_key="abc123", timeout=30)
    assert cfg.is_configured is True


# ----- R2InspectConfig from_dict -----

def test_r2inspect_config_from_dict_with_all_sections() -> None:
    data = {
        "general": {"verbose": True, "max_strings": 500},
        "yara": {"timeout": 120},
        "packer": {"entropy_threshold": 6.5},
        "crypto": {"enabled": True},
        "strings": {"min_length": 5, "max_length": 50},
        "output": {"json_indent": 4, "csv_delimiter": ";"},
        "virustotal": {"timeout": 60},
        "analysis": {"deep_analysis": True},
        "pe_analysis": {"analyze_resources": False},
        "pipeline": {"max_workers": 2},
    }
    cfg = R2InspectConfig.from_dict(data)
    assert cfg.general.verbose is True
    assert cfg.general.max_strings == 500
    assert cfg.yara.timeout == 120
    assert cfg.packer.entropy_threshold == 6.5
    assert cfg.strings.min_length == 5
    assert cfg.output.json_indent == 4
    assert cfg.virustotal.timeout == 60
    assert cfg.analysis.deep_analysis is True
    assert cfg.pe_analysis.analyze_resources is False
    assert cfg.pipeline.max_workers == 2


def test_r2inspect_config_from_dict_non_dict_raises() -> None:
    with pytest.raises(TypeError, match="must be a dictionary"):
        R2InspectConfig.from_dict("not a dict")  # type: ignore


def test_r2inspect_config_to_dict_roundtrip() -> None:
    cfg = R2InspectConfig()
    d = cfg.to_dict()
    cfg2 = R2InspectConfig.from_dict(d)
    assert cfg2.general.verbose == cfg.general.verbose
    assert cfg2.yara.timeout == cfg.yara.timeout


def test_r2inspect_config_merge() -> None:
    base = R2InspectConfig(general=GeneralConfig(verbose=False))
    override = R2InspectConfig(general=GeneralConfig(verbose=True))
    merged = base.merge(override)
    assert merged.general.verbose is True


def test_r2inspect_config_from_dict_empty() -> None:
    cfg = R2InspectConfig.from_dict({})
    assert isinstance(cfg, R2InspectConfig)
    assert cfg.general.verbose is False


# ----- ConfigStore -----

def test_config_store_load_returns_dict(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text('{"key": "value"}')
    result = ConfigStore.load(str(path))
    assert result == {"key": "value"}


def test_config_store_load_missing_returns_none(tmp_path) -> None:
    result = ConfigStore.load(str(tmp_path / "missing.json"))
    assert result is None


def test_config_store_load_invalid_json_returns_none(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not valid json {{{")
    result = ConfigStore.load(str(path))
    assert result is None


def test_config_store_load_non_dict_json_returns_none(tmp_path) -> None:
    path = tmp_path / "array.json"
    path.write_text("[1, 2, 3]")
    result = ConfigStore.load(str(path))
    assert result is None


def test_config_store_save_creates_file(tmp_path) -> None:
    path = tmp_path / "subdir" / "cfg.json"
    ConfigStore.save(str(path), {"x": 1})
    assert path.exists()
    loaded = ConfigStore.load(str(path))
    assert loaded == {"x": 1}


def test_config_store_save_nested_dict(tmp_path) -> None:
    path = tmp_path / "nested.json"
    payload = {"general": {"verbose": True, "max_strings": 500}}
    ConfigStore.save(str(path), payload)
    loaded = ConfigStore.load(str(path))
    assert loaded == payload
