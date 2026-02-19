"""Tests for ConfigBuilder fluent methods and factory functions in builder.py."""

from __future__ import annotations

import pytest

from r2inspect.config_schemas.builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)
from r2inspect.config_schemas.schemas import (
    AnalysisConfig,
    CryptoConfig,
    GeneralConfig,
    OutputConfig,
    PackerConfig,
    PEAnalysisConfig,
    R2InspectConfig,
    StringsConfig,
    VirusTotalConfig,
    YaraConfig,
)


# ---------------------------------------------------------------------------
# ConfigBuilder initialisation
# ---------------------------------------------------------------------------

def test_config_builder_init_creates_empty_kwargs() -> None:
    builder = ConfigBuilder()
    assert builder._general_kwargs == {}
    assert builder._yara_kwargs == {}
    assert builder._packer_kwargs == {}
    assert builder._crypto_kwargs == {}
    assert builder._strings_kwargs == {}
    assert builder._output_kwargs == {}
    assert builder._virustotal_kwargs == {}
    assert builder._analysis_kwargs == {}
    assert builder._pe_analysis_kwargs == {}


# ---------------------------------------------------------------------------
# General configuration methods
# ---------------------------------------------------------------------------

def test_with_verbose_stores_true() -> None:
    builder = ConfigBuilder().with_verbose(True)
    assert builder._general_kwargs["verbose"] is True


def test_with_verbose_stores_false() -> None:
    builder = ConfigBuilder().with_verbose(False)
    assert builder._general_kwargs["verbose"] is False


def test_with_max_strings_stores_value() -> None:
    builder = ConfigBuilder().with_max_strings(500)
    assert builder._general_kwargs["max_strings"] == 500


def test_with_string_length_range_stores_both_bounds() -> None:
    builder = ConfigBuilder().with_string_length_range(3, 200)
    assert builder._general_kwargs["min_string_length"] == 3
    assert builder._general_kwargs["max_string_length"] == 200


# ---------------------------------------------------------------------------
# YARA configuration methods
# ---------------------------------------------------------------------------

def test_with_yara_rules_stores_path() -> None:
    builder = ConfigBuilder().with_yara_rules("/rules/malware")
    assert builder._yara_kwargs["rules_path"] == "/rules/malware"


def test_with_yara_enabled_stores_flag() -> None:
    builder = ConfigBuilder().with_yara_enabled(False)
    assert builder._yara_kwargs["enabled"] is False


def test_with_yara_timeout_stores_value() -> None:
    builder = ConfigBuilder().with_yara_timeout(30)
    assert builder._yara_kwargs["timeout"] == 30


# ---------------------------------------------------------------------------
# Packer configuration methods
# ---------------------------------------------------------------------------

def test_with_packer_detection_stores_flag() -> None:
    builder = ConfigBuilder().with_packer_detection(False)
    assert builder._packer_kwargs["enabled"] is False


def test_with_entropy_threshold_stores_value() -> None:
    builder = ConfigBuilder().with_entropy_threshold(6.5)
    assert builder._packer_kwargs["entropy_threshold"] == pytest.approx(6.5)


def test_with_section_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_section_analysis(False)
    assert builder._packer_kwargs["section_analysis"] is False


# ---------------------------------------------------------------------------
# Crypto configuration methods
# ---------------------------------------------------------------------------

def test_with_crypto_detection_stores_flag() -> None:
    builder = ConfigBuilder().with_crypto_detection(False)
    assert builder._crypto_kwargs["enabled"] is False


def test_with_crypto_constants_stores_flag() -> None:
    builder = ConfigBuilder().with_crypto_constants(False)
    assert builder._crypto_kwargs["detect_constants"] is False


def test_with_base64_detection_stores_flag() -> None:
    builder = ConfigBuilder().with_base64_detection(False)
    assert builder._crypto_kwargs["detect_base64"] is False


# ---------------------------------------------------------------------------
# Strings configuration methods
# ---------------------------------------------------------------------------

def test_with_string_min_length_stores_value() -> None:
    builder = ConfigBuilder().with_string_min_length(6)
    assert builder._strings_kwargs["min_length"] == 6


def test_with_string_max_length_stores_value() -> None:
    builder = ConfigBuilder().with_string_max_length(256)
    assert builder._strings_kwargs["max_length"] == 256


def test_with_unicode_extraction_stores_flag() -> None:
    builder = ConfigBuilder().with_unicode_extraction(False)
    assert builder._strings_kwargs["extract_unicode"] is False


def test_with_ascii_extraction_stores_flag() -> None:
    builder = ConfigBuilder().with_ascii_extraction(False)
    assert builder._strings_kwargs["extract_ascii"] is False


# ---------------------------------------------------------------------------
# Output configuration methods
# ---------------------------------------------------------------------------

def test_with_json_indent_stores_value() -> None:
    builder = ConfigBuilder().with_json_indent(4)
    assert builder._output_kwargs["json_indent"] == 4


def test_with_csv_delimiter_stores_value() -> None:
    builder = ConfigBuilder().with_csv_delimiter("|")
    assert builder._output_kwargs["csv_delimiter"] == "|"


def test_with_progress_display_stores_flag() -> None:
    builder = ConfigBuilder().with_progress_display(False)
    assert builder._output_kwargs["show_progress"] is False


# ---------------------------------------------------------------------------
# VirusTotal configuration methods
# ---------------------------------------------------------------------------

def test_with_virustotal_stores_api_key_and_enabled_flag() -> None:
    builder = ConfigBuilder().with_virustotal("my_api_key", enabled=True)
    assert builder._virustotal_kwargs["api_key"] == "my_api_key"
    assert builder._virustotal_kwargs["enabled"] is True


def test_with_virustotal_timeout_stores_value() -> None:
    builder = ConfigBuilder().with_virustotal_timeout(60)
    assert builder._virustotal_kwargs["timeout"] == 60


# ---------------------------------------------------------------------------
# Analysis configuration methods
# ---------------------------------------------------------------------------

def test_with_deep_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_deep_analysis(True)
    assert builder._analysis_kwargs["deep_analysis"] is True


def test_with_function_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_function_analysis(False)
    assert builder._analysis_kwargs["function_analysis"] is False


def test_with_graph_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_graph_analysis(True)
    assert builder._analysis_kwargs["graph_analysis"] is True


# ---------------------------------------------------------------------------
# PE analysis configuration methods
# ---------------------------------------------------------------------------

def test_with_authenticode_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_authenticode_analysis(True)
    assert builder._pe_analysis_kwargs["analyze_authenticode"] is True


def test_with_overlay_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_overlay_analysis(False)
    assert builder._pe_analysis_kwargs["analyze_overlay"] is False


def test_with_resource_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_resource_analysis(True)
    assert builder._pe_analysis_kwargs["analyze_resources"] is True


def test_with_mitigation_analysis_stores_flag() -> None:
    builder = ConfigBuilder().with_mitigation_analysis(False)
    assert builder._pe_analysis_kwargs["analyze_mitigations"] is False


# ---------------------------------------------------------------------------
# build() - empty kwargs branches (else-branches for each sub-config)
# ---------------------------------------------------------------------------

def test_build_empty_builder_uses_all_defaults() -> None:
    cfg = ConfigBuilder().build()
    assert isinstance(cfg, R2InspectConfig)
    assert isinstance(cfg.general, GeneralConfig)
    assert isinstance(cfg.yara, YaraConfig)
    assert isinstance(cfg.packer, PackerConfig)
    assert isinstance(cfg.crypto, CryptoConfig)
    assert isinstance(cfg.strings, StringsConfig)
    assert isinstance(cfg.output, OutputConfig)
    assert isinstance(cfg.virustotal, VirusTotalConfig)
    assert isinstance(cfg.analysis, AnalysisConfig)
    assert isinstance(cfg.pe_analysis, PEAnalysisConfig)


def test_build_with_only_general_kwargs_uses_defaults_for_rest() -> None:
    cfg = ConfigBuilder().with_verbose(True).build()
    assert cfg.general.verbose is True
    assert isinstance(cfg.virustotal, VirusTotalConfig)
    assert isinstance(cfg.analysis, AnalysisConfig)
    assert isinstance(cfg.pe_analysis, PEAnalysisConfig)


def test_build_with_virustotal_kwargs_creates_populated_config() -> None:
    cfg = ConfigBuilder().with_virustotal("apikey123").build()
    assert cfg.virustotal.api_key == "apikey123"


def test_build_with_analysis_kwargs_creates_populated_config() -> None:
    cfg = ConfigBuilder().with_deep_analysis(True).build()
    assert cfg.analysis.deep_analysis is True


def test_build_with_pe_analysis_kwargs_creates_populated_config() -> None:
    cfg = ConfigBuilder().with_overlay_analysis(True).build()
    assert cfg.pe_analysis.analyze_overlay is True


# ---------------------------------------------------------------------------
# Fluent chaining returns self
# ---------------------------------------------------------------------------

def test_all_builder_methods_return_builder_instance() -> None:
    builder = ConfigBuilder()
    assert builder.with_verbose() is builder
    assert builder.with_max_strings(10) is builder
    assert builder.with_string_length_range(1, 50) is builder
    assert builder.with_yara_rules("r") is builder
    assert builder.with_yara_enabled() is builder
    assert builder.with_yara_timeout(10) is builder
    assert builder.with_packer_detection() is builder
    assert builder.with_entropy_threshold(7.0) is builder
    assert builder.with_section_analysis() is builder
    assert builder.with_crypto_detection() is builder
    assert builder.with_crypto_constants() is builder
    assert builder.with_base64_detection() is builder
    assert builder.with_string_min_length(4) is builder
    assert builder.with_string_max_length(100) is builder
    assert builder.with_unicode_extraction() is builder
    assert builder.with_ascii_extraction() is builder
    assert builder.with_json_indent(2) is builder
    assert builder.with_csv_delimiter(",") is builder
    assert builder.with_progress_display() is builder
    assert builder.with_virustotal("k") is builder
    assert builder.with_virustotal_timeout(30) is builder
    assert builder.with_deep_analysis() is builder
    assert builder.with_function_analysis() is builder
    assert builder.with_graph_analysis() is builder
    assert builder.with_authenticode_analysis() is builder
    assert builder.with_overlay_analysis() is builder
    assert builder.with_resource_analysis() is builder
    assert builder.with_mitigation_analysis() is builder


# ---------------------------------------------------------------------------
# Factory convenience functions
# ---------------------------------------------------------------------------

def test_create_default_config_returns_r2inspect_config() -> None:
    cfg = create_default_config()
    assert isinstance(cfg, R2InspectConfig)
    assert cfg.general.verbose is False


def test_create_verbose_config_enables_verbose() -> None:
    cfg = create_verbose_config()
    assert cfg.general.verbose is True


def test_create_minimal_config_disables_heavy_modules() -> None:
    cfg = create_minimal_config()
    assert cfg.packer.enabled is False
    assert cfg.crypto.enabled is False
    assert cfg.yara.enabled is False
    assert cfg.analysis.function_analysis is False


def test_create_full_analysis_config_enables_all_modules() -> None:
    cfg = create_full_analysis_config()
    assert cfg.general.verbose is True
    assert cfg.analysis.deep_analysis is True
    assert cfg.analysis.function_analysis is True
    assert cfg.analysis.graph_analysis is True
    assert cfg.packer.enabled is True
    assert cfg.crypto.enabled is True
    assert cfg.yara.enabled is True
