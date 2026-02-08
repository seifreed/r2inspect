from __future__ import annotations

import pytest

from r2inspect.config_schemas.schemas import (
    GeneralConfig,
    OutputConfig,
    PackerConfig,
    R2InspectConfig,
    StringsConfig,
    VirusTotalConfig,
    YaraConfig,
)


def test_schema_validation_errors():
    with pytest.raises(ValueError):
        GeneralConfig(max_strings=-1)

    with pytest.raises(ValueError):
        GeneralConfig(min_string_length=0)

    with pytest.raises(ValueError):
        GeneralConfig(min_string_length=5, max_string_length=4)

    with pytest.raises(ValueError):
        YaraConfig(timeout=0)

    with pytest.raises(ValueError):
        PackerConfig(entropy_threshold=-0.1)

    with pytest.raises(ValueError):
        PackerConfig(entropy_threshold=9.1)

    with pytest.raises(ValueError):
        StringsConfig(min_length=0)

    with pytest.raises(ValueError):
        StringsConfig(min_length=5, max_length=4)

    with pytest.raises(ValueError):
        OutputConfig(json_indent=-1)

    with pytest.raises(ValueError):
        OutputConfig(csv_delimiter="::")

    with pytest.raises(ValueError):
        VirusTotalConfig(timeout=0)


def test_virustotal_is_configured():
    assert VirusTotalConfig().is_configured is False
    assert VirusTotalConfig(api_key="", enabled=True).is_configured is False
    assert VirusTotalConfig(api_key="key", enabled=True).is_configured is True


def test_r2inspect_config_from_dict_type_error():
    with pytest.raises(TypeError):
        R2InspectConfig.from_dict("not-a-dict")
