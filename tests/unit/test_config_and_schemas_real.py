from __future__ import annotations

import json
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.config_schemas import builder
from r2inspect.config_schemas.schemas import (
    GeneralConfig,
    OutputConfig,
    PackerConfig,
    R2InspectConfig,
    VirusTotalConfig,
    YaraConfig,
)
from r2inspect.config_store import ConfigStore


def test_config_store_load_save(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    payload = {"general": {"verbose": True}}
    ConfigStore.save(str(path), payload)
    assert ConfigStore.load(str(path)) == payload

    path.write_text(json.dumps(["not", "dict"]), encoding="utf-8")
    assert ConfigStore.load(str(path)) is None

    assert ConfigStore.load(str(tmp_path / "missing.json")) is None


def test_config_load_apply_overrides_and_set(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    config = Config(config_path=str(path))
    assert path.exists()
    assert config.to_dict()["general"]["verbose"] is False

    config.apply_overrides({"general": {"verbose": True}, "extra": {"x": 1}})
    assert config.to_dict()["general"]["verbose"] is True
    assert config.to_dict()["extra"]["x"] == 1

    config.set("general", "max_strings", 123)
    assert config.to_dict()["general"]["max_strings"] == 123

    config.set("new_section", "flag", True)
    assert config.to_dict()["new_section"]["flag"] is True


def test_config_invalid_values_fallback(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"general": {"max_strings": -1}}), encoding="utf-8")
    config = Config(config_path=str(path))
    assert (
        config.typed_config.general.max_strings == Config.DEFAULT_CONFIG["general"]["max_strings"]
    )


def test_config_helpers_and_properties(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    config = Config(config_path=str(path))

    rules_path = config.get_yara_rules_path()
    assert "rules" in rules_path

    config.apply_overrides({"virustotal": {"enabled": True, "api_key": "k"}})
    assert config.is_virustotal_enabled() is True
    assert config.get_virustotal_api_key() == "k"

    assert config.analyze_authenticode is True
    assert config.analyze_overlay is True
    assert config.analyze_resources is True
    assert config.analyze_mitigations is True


def test_config_schemas_validation_and_merge() -> None:
    with pytest.raises(ValueError):
        GeneralConfig(max_strings=-1)

    with pytest.raises(ValueError):
        YaraConfig(timeout=0)

    with pytest.raises(ValueError):
        PackerConfig(entropy_threshold=9.0)

    with pytest.raises(ValueError):
        OutputConfig(csv_delimiter="||")

    vt = VirusTotalConfig(api_key="k", enabled=True, timeout=5)
    assert vt.is_configured is True

    with pytest.raises(TypeError):
        R2InspectConfig.from_dict([])

    merged = R2InspectConfig().merge(R2InspectConfig())
    assert isinstance(merged, R2InspectConfig)


def test_config_builder_variants() -> None:
    default_config = builder.create_default_config()
    verbose_config = builder.create_verbose_config()
    minimal_config = builder.create_minimal_config()
    full_config = builder.create_full_analysis_config()

    assert default_config.general.verbose is False
    assert verbose_config.general.verbose is True
    assert minimal_config.packer.enabled is False
    assert full_config.analysis.graph_analysis is True
