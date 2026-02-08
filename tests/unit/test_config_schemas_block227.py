from __future__ import annotations

from r2inspect.config_schemas.builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)
from r2inspect.config_schemas.schemas import R2InspectConfig


def test_config_builder_variants() -> None:
    default = create_default_config()
    verbose = create_verbose_config()
    minimal = create_minimal_config()
    full = create_full_analysis_config()

    assert default.general.verbose is False
    assert verbose.general.verbose is True
    assert minimal.packer.enabled is False
    assert full.analysis.deep_analysis is True


def test_config_builder_custom() -> None:
    builder = (
        ConfigBuilder()
        .with_verbose(True)
        .with_yara_timeout(10)
        .with_entropy_threshold(6.5)
        .with_string_length_range(3, 50)
        .with_json_indent(4)
        .with_csv_delimiter(";")
    )
    config = builder.build()
    assert config.general.verbose is True
    assert config.yara.timeout == 10
    assert config.packer.entropy_threshold == 6.5
    assert config.general.min_string_length == 3
    assert config.general.max_string_length == 50
    assert config.output.json_indent == 4
    assert config.output.csv_delimiter == ";"


def test_config_schema_from_dict() -> None:
    config = R2InspectConfig.from_dict({"general": {"verbose": True}})
    assert config.general.verbose is True
