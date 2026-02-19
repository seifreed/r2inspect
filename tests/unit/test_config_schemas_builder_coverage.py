"""Coverage tests for r2inspect/config_schemas/builder.py"""

from r2inspect.config_schemas.builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)
from r2inspect.config_schemas.schemas import R2InspectConfig


# Basic builder tests

def test_config_builder_default_build():
    config = ConfigBuilder().build()
    assert isinstance(config, R2InspectConfig)


def test_config_builder_with_verbose_true():
    config = ConfigBuilder().with_verbose(True).build()
    assert config.general.verbose is True


def test_config_builder_with_verbose_false():
    config = ConfigBuilder().with_verbose(False).build()
    assert config.general.verbose is False


def test_config_builder_with_max_strings():
    config = ConfigBuilder().with_max_strings(500).build()
    assert config.general.max_strings == 500


def test_config_builder_with_string_length_range():
    config = ConfigBuilder().with_string_length_range(8, 200).build()
    assert config.general.min_string_length == 8
    assert config.general.max_string_length == 200


def test_config_builder_with_yara_rules():
    config = ConfigBuilder().with_yara_rules("/path/to/rules").build()
    assert config.yara.rules_path == "/path/to/rules"


def test_config_builder_with_yara_enabled_true():
    config = ConfigBuilder().with_yara_enabled(True).build()
    assert config.yara.enabled is True


def test_config_builder_with_yara_enabled_false():
    config = ConfigBuilder().with_yara_enabled(False).build()
    assert config.yara.enabled is False


def test_config_builder_with_yara_timeout():
    config = ConfigBuilder().with_yara_timeout(120).build()
    assert config.yara.timeout == 120


def test_config_builder_with_packer_detection_enabled():
    config = ConfigBuilder().with_packer_detection(True).build()
    assert config.packer.enabled is True


def test_config_builder_with_packer_detection_disabled():
    config = ConfigBuilder().with_packer_detection(False).build()
    assert config.packer.enabled is False


def test_config_builder_with_entropy_threshold():
    config = ConfigBuilder().with_entropy_threshold(6.5).build()
    assert config.packer.entropy_threshold == 6.5


def test_config_builder_with_section_analysis_enabled():
    config = ConfigBuilder().with_section_analysis(True).build()
    assert config.packer.section_analysis is True


def test_config_builder_with_section_analysis_disabled():
    config = ConfigBuilder().with_section_analysis(False).build()
    assert config.packer.section_analysis is False


def test_config_builder_with_crypto_detection_enabled():
    config = ConfigBuilder().with_crypto_detection(True).build()
    assert config.crypto.enabled is True


def test_config_builder_with_crypto_detection_disabled():
    config = ConfigBuilder().with_crypto_detection(False).build()
    assert config.crypto.enabled is False


def test_config_builder_with_crypto_constants():
    config = ConfigBuilder().with_crypto_constants(True).build()
    assert config.crypto.detect_constants is True


def test_config_builder_with_crypto_constants_disabled():
    config = ConfigBuilder().with_crypto_constants(False).build()
    assert config.crypto.detect_constants is False


def test_config_builder_with_base64_detection():
    config = ConfigBuilder().with_base64_detection(True).build()
    assert config.crypto.detect_base64 is True


def test_config_builder_with_base64_detection_disabled():
    config = ConfigBuilder().with_base64_detection(False).build()
    assert config.crypto.detect_base64 is False


def test_config_builder_with_string_min_length():
    config = ConfigBuilder().with_string_min_length(6).build()
    assert config.strings.min_length == 6


def test_config_builder_with_string_max_length():
    config = ConfigBuilder().with_string_max_length(150).build()
    assert config.strings.max_length == 150


def test_config_builder_with_unicode_extraction():
    config = ConfigBuilder().with_unicode_extraction(True).build()
    assert config.strings.extract_unicode is True


def test_config_builder_with_unicode_extraction_disabled():
    config = ConfigBuilder().with_unicode_extraction(False).build()
    assert config.strings.extract_unicode is False


def test_config_builder_with_ascii_extraction():
    config = ConfigBuilder().with_ascii_extraction(True).build()
    assert config.strings.extract_ascii is True


def test_config_builder_with_ascii_extraction_disabled():
    config = ConfigBuilder().with_ascii_extraction(False).build()
    assert config.strings.extract_ascii is False


def test_config_builder_with_json_indent():
    config = ConfigBuilder().with_json_indent(4).build()
    assert config.output.json_indent == 4


def test_config_builder_with_csv_delimiter():
    config = ConfigBuilder().with_csv_delimiter(";").build()
    assert config.output.csv_delimiter == ";"


def test_config_builder_with_progress_display():
    config = ConfigBuilder().with_progress_display(True).build()
    assert config.output.show_progress is True


def test_config_builder_with_progress_display_disabled():
    config = ConfigBuilder().with_progress_display(False).build()
    assert config.output.show_progress is False


def test_config_builder_with_virustotal():
    config = ConfigBuilder().with_virustotal("my_api_key_123").build()
    assert config.virustotal.api_key == "my_api_key_123"
    assert config.virustotal.enabled is True


def test_config_builder_with_virustotal_disabled():
    config = ConfigBuilder().with_virustotal("key", enabled=False).build()
    assert config.virustotal.enabled is False


def test_config_builder_with_virustotal_timeout():
    config = ConfigBuilder().with_virustotal_timeout(30).build()
    assert config.virustotal.timeout == 30


def test_config_builder_with_deep_analysis():
    config = ConfigBuilder().with_deep_analysis(True).build()
    assert config.analysis.deep_analysis is True


def test_config_builder_with_deep_analysis_disabled():
    config = ConfigBuilder().with_deep_analysis(False).build()
    assert config.analysis.deep_analysis is False


def test_config_builder_with_function_analysis():
    config = ConfigBuilder().with_function_analysis(True).build()
    assert config.analysis.function_analysis is True


def test_config_builder_with_function_analysis_disabled():
    config = ConfigBuilder().with_function_analysis(False).build()
    assert config.analysis.function_analysis is False


def test_config_builder_with_graph_analysis():
    config = ConfigBuilder().with_graph_analysis(True).build()
    assert config.analysis.graph_analysis is True


def test_config_builder_with_graph_analysis_disabled():
    config = ConfigBuilder().with_graph_analysis(False).build()
    assert config.analysis.graph_analysis is False


def test_config_builder_with_authenticode_analysis():
    config = ConfigBuilder().with_authenticode_analysis(True).build()
    assert config.pe_analysis.analyze_authenticode is True


def test_config_builder_with_authenticode_analysis_disabled():
    config = ConfigBuilder().with_authenticode_analysis(False).build()
    assert config.pe_analysis.analyze_authenticode is False


def test_config_builder_with_overlay_analysis():
    config = ConfigBuilder().with_overlay_analysis(True).build()
    assert config.pe_analysis.analyze_overlay is True


def test_config_builder_with_overlay_analysis_disabled():
    config = ConfigBuilder().with_overlay_analysis(False).build()
    assert config.pe_analysis.analyze_overlay is False


def test_config_builder_with_resource_analysis():
    config = ConfigBuilder().with_resource_analysis(True).build()
    assert config.pe_analysis.analyze_resources is True


def test_config_builder_with_resource_analysis_disabled():
    config = ConfigBuilder().with_resource_analysis(False).build()
    assert config.pe_analysis.analyze_resources is False


def test_config_builder_with_mitigation_analysis():
    config = ConfigBuilder().with_mitigation_analysis(True).build()
    assert config.pe_analysis.analyze_mitigations is True


def test_config_builder_with_mitigation_analysis_disabled():
    config = ConfigBuilder().with_mitigation_analysis(False).build()
    assert config.pe_analysis.analyze_mitigations is False


def test_config_builder_chaining_returns_builder():
    builder = ConfigBuilder()
    result = builder.with_verbose(True)
    assert result is builder


def test_config_builder_all_options_chain():
    config = (
        ConfigBuilder()
        .with_verbose(True)
        .with_max_strings(2000)
        .with_string_length_range(5, 120)
        .with_yara_rules("/rules")
        .with_yara_enabled(True)
        .with_yara_timeout(90)
        .with_packer_detection(True)
        .with_entropy_threshold(7.5)
        .with_section_analysis(True)
        .with_crypto_detection(True)
        .with_crypto_constants(True)
        .with_base64_detection(True)
        .with_string_min_length(5)
        .with_string_max_length(120)
        .with_unicode_extraction(True)
        .with_ascii_extraction(True)
        .with_json_indent(2)
        .with_csv_delimiter(",")
        .with_progress_display(True)
        .with_deep_analysis(True)
        .with_function_analysis(True)
        .with_graph_analysis(True)
        .with_authenticode_analysis(True)
        .with_overlay_analysis(True)
        .with_resource_analysis(True)
        .with_mitigation_analysis(True)
        .build()
    )
    assert isinstance(config, R2InspectConfig)
    assert config.general.verbose is True
    assert config.general.max_strings == 2000


# Factory function tests

def test_create_default_config():
    config = create_default_config()
    assert isinstance(config, R2InspectConfig)
    assert config.general.verbose is False


def test_create_verbose_config():
    config = create_verbose_config()
    assert isinstance(config, R2InspectConfig)
    assert config.general.verbose is True


def test_create_minimal_config():
    config = create_minimal_config()
    assert isinstance(config, R2InspectConfig)
    assert config.packer.enabled is False
    assert config.crypto.enabled is False
    assert config.yara.enabled is False
    assert config.analysis.function_analysis is False


def test_create_full_analysis_config():
    config = create_full_analysis_config()
    assert isinstance(config, R2InspectConfig)
    assert config.general.verbose is True
    assert config.analysis.deep_analysis is True
    assert config.analysis.function_analysis is True
    assert config.analysis.graph_analysis is True
    assert config.packer.enabled is True
    assert config.crypto.enabled is True
    assert config.yara.enabled is True
