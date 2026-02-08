from __future__ import annotations

from r2inspect.config_schemas.builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)


def test_config_builder_all_fluent_methods() -> None:
    cfg = (
        ConfigBuilder()
        .with_verbose(True)
        .with_max_strings(111)
        .with_string_length_range(4, 222)
        .with_yara_rules("rules")
        .with_yara_enabled(True)
        .with_yara_timeout(15)
        .with_packer_detection(True)
        .with_entropy_threshold(7.3)
        .with_section_analysis(True)
        .with_crypto_detection(True)
        .with_crypto_constants(True)
        .with_base64_detection(True)
        .with_string_min_length(5)
        .with_string_max_length(333)
        .with_unicode_extraction(True)
        .with_ascii_extraction(True)
        .with_json_indent(2)
        .with_csv_delimiter(";")
        .with_progress_display(False)
        .with_virustotal("key", enabled=True)
        .with_virustotal_timeout(30)
        .with_deep_analysis(True)
        .with_function_analysis(True)
        .with_graph_analysis(True)
        .with_authenticode_analysis(True)
        .with_overlay_analysis(True)
        .with_resource_analysis(True)
        .with_mitigation_analysis(True)
        .build()
    )

    assert cfg.general.verbose is True
    assert cfg.general.max_strings == 111
    assert cfg.general.min_string_length == 4
    assert cfg.general.max_string_length == 222
    assert cfg.yara.rules_path == "rules"
    assert cfg.yara.enabled is True
    assert cfg.yara.timeout == 15
    assert cfg.packer.enabled is True
    assert cfg.packer.entropy_threshold == 7.3
    assert cfg.packer.section_analysis is True
    assert cfg.crypto.enabled is True
    assert cfg.crypto.detect_constants is True
    assert cfg.crypto.detect_base64 is True
    assert cfg.strings.min_length == 5
    assert cfg.strings.max_length == 333
    assert cfg.strings.extract_unicode is True
    assert cfg.strings.extract_ascii is True
    assert cfg.output.json_indent == 2
    assert cfg.output.csv_delimiter == ";"
    assert cfg.output.show_progress is False
    assert cfg.virustotal.api_key == "key"
    assert cfg.virustotal.enabled is True
    assert cfg.virustotal.timeout == 30
    assert cfg.analysis.deep_analysis is True
    assert cfg.analysis.function_analysis is True
    assert cfg.analysis.graph_analysis is True
    assert cfg.pe_analysis.analyze_authenticode is True
    assert cfg.pe_analysis.analyze_overlay is True
    assert cfg.pe_analysis.analyze_resources is True
    assert cfg.pe_analysis.analyze_mitigations is True


def test_builder_predefined_configs() -> None:
    default_cfg = create_default_config()
    verbose_cfg = create_verbose_config()
    minimal_cfg = create_minimal_config()
    full_cfg = create_full_analysis_config()

    assert default_cfg.general is not None
    assert verbose_cfg.general.verbose is True
    assert minimal_cfg.packer.enabled is False
    assert minimal_cfg.crypto.enabled is False
    assert minimal_cfg.yara.enabled is False
    assert minimal_cfg.analysis.function_analysis is False
    assert full_cfg.general.verbose is True
    assert full_cfg.analysis.deep_analysis is True
    assert full_cfg.analysis.function_analysis is True
    assert full_cfg.analysis.graph_analysis is True
    assert full_cfg.packer.enabled is True
    assert full_cfg.crypto.enabled is True
    assert full_cfg.yara.enabled is True
