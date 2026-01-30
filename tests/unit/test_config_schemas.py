import pytest

from r2inspect.config_schemas.builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)
from r2inspect.config_schemas.schemas import (
    GeneralConfig,
    OutputConfig,
    R2InspectConfig,
    VirusTotalConfig,
)


def test_general_config_validation():
    with pytest.raises(ValueError):
        GeneralConfig(max_strings=-1)
    with pytest.raises(ValueError):
        GeneralConfig(min_string_length=0)
    with pytest.raises(ValueError):
        GeneralConfig(min_string_length=10, max_string_length=5)


def test_output_config_validation():
    with pytest.raises(ValueError):
        OutputConfig(json_indent=-1)
    with pytest.raises(ValueError):
        OutputConfig(csv_delimiter="::")


def test_virustotal_is_configured():
    vt = VirusTotalConfig(api_key="abc", enabled=True)
    assert vt.is_configured is True
    vt_disabled = VirusTotalConfig(api_key="", enabled=True)
    assert vt_disabled.is_configured is False


def test_r2inspect_config_from_dict_and_merge():
    base = R2InspectConfig.from_dict({"general": {"verbose": True}})
    assert base.general.verbose is True

    override = R2InspectConfig.from_dict({"general": {"max_strings": 10}})
    merged = base.merge(override)
    # merge is dict-based, so section dictionaries are replaced by the override
    assert merged.general.verbose is False
    assert merged.general.max_strings == 10


def test_config_builder_chain_builds():
    config = (
        ConfigBuilder()
        .with_verbose(True)
        .with_yara_rules("/rules")
        .with_yara_timeout(120)
        .with_entropy_threshold(6.5)
        .with_string_length_range(5, 20)
        .with_csv_delimiter(";")
        .with_virustotal("key", enabled=True)
        .with_deep_analysis(True)
        .with_mitigation_analysis(False)
        .build()
    )

    assert config.general.verbose is True
    assert config.yara.rules_path == "/rules"
    assert config.yara.timeout == 120
    assert config.packer.entropy_threshold == 6.5
    assert config.general.min_string_length == 5
    assert config.general.max_string_length == 20
    assert config.output.csv_delimiter == ";"
    assert config.virustotal.api_key == "key"
    assert config.analysis.deep_analysis is True
    assert config.pe_analysis.analyze_mitigations is False


def test_builder_helpers():
    default_cfg = create_default_config()
    assert default_cfg.general.verbose is False

    verbose_cfg = create_verbose_config()
    assert verbose_cfg.general.verbose is True

    minimal_cfg = create_minimal_config()
    assert minimal_cfg.packer.enabled is False
    assert minimal_cfg.crypto.enabled is False
    assert minimal_cfg.yara.enabled is False
    assert minimal_cfg.analysis.function_analysis is False

    full_cfg = create_full_analysis_config()
    assert full_cfg.general.verbose is True
    assert full_cfg.analysis.deep_analysis is True
    assert full_cfg.analysis.graph_analysis is True
    assert full_cfg.packer.enabled is True
