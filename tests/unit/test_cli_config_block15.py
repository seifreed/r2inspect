from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from r2inspect.cli.commands.base import (
    Command,
    CommandContext,
    apply_thread_settings,
    configure_quiet_logging,
)
from r2inspect.cli.commands.config_command import ConfigCommand
from r2inspect.cli.validators import (
    handle_xor_input,
    sanitize_xor_string,
    validate_batch_input,
    validate_config_input,
    validate_extensions_input,
    validate_file_input,
    validate_input_mode,
    validate_output_input,
    validate_single_file,
    validate_threads_input,
    validate_yara_input,
)
from r2inspect.config import Config
from r2inspect.config_schemas.builder import (
    ConfigBuilder,
    create_default_config,
    create_full_analysis_config,
    create_minimal_config,
    create_verbose_config,
)


class _DummyCommand(Command):
    def execute(self, args: dict[str, object]) -> int:  # pragma: no cover - not used
        return 0


def _make_config(tmp_path: Path) -> Config:
    return Config(str(tmp_path / "config.json"))


def test_configure_quiet_logging_sets_levels():
    configure_quiet_logging(True)
    assert logging.getLogger("r2pipe").level == logging.CRITICAL
    assert logging.getLogger("r2inspect").level == logging.WARNING


def test_apply_thread_settings_valid_and_invalid(tmp_path: Path):
    config = _make_config(tmp_path)
    apply_thread_settings(config, 4)
    assert config.typed_config.pipeline.max_workers == 4
    assert config.typed_config.pipeline.parallel_execution is True

    apply_thread_settings(config, 1)
    assert config.typed_config.pipeline.max_workers == 1
    assert config.typed_config.pipeline.parallel_execution is False

    before = config.to_dict()
    apply_thread_settings(config, "not-a-number")
    assert config.to_dict() == before


def test_command_context_create_defaults():
    ctx = CommandContext.create(verbose=True, quiet=True)
    assert ctx.config is not None
    assert ctx.verbose is True
    assert ctx.quiet is True
    assert ctx.logger is not None


def test_command_context_lazy_init(tmp_path: Path):
    cmd = _DummyCommand()
    assert cmd.context.config is not None

    config = _make_config(tmp_path)
    ctx = CommandContext.create(config=config)
    cmd.context = ctx
    assert cmd.context.config is config


def test_command_get_config_prefers_path(tmp_path: Path):
    config_path = tmp_path / "custom.json"
    config_path.write_text(json.dumps({"general": {"verbose": True}}))

    cmd = _DummyCommand()
    cfg = cmd._get_config(str(config_path))
    assert cfg.typed_config.general.verbose is True


def test_setup_analysis_options():
    cmd = _DummyCommand()
    assert cmd._setup_analysis_options() == {}
    assert cmd._setup_analysis_options(yara="rules") == {"yara_rules_dir": "rules"}
    assert cmd._setup_analysis_options(xor="AA") == {"xor_search": "AA"}
    assert cmd._setup_analysis_options(yara="rules", xor="AA") == {
        "yara_rules_dir": "rules",
        "xor_search": "AA",
    }


def test_config_command_yara_listing(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cmd = ConfigCommand(CommandContext.create())

    missing = cmd._list_yara_rules(yara_path=str(tmp_path / "missing"))
    assert missing == 1

    empty_dir = tmp_path / "rules"
    empty_dir.mkdir()
    empty = cmd._list_yara_rules(yara_path=str(empty_dir))
    assert empty == 0

    (empty_dir / "root.yar").write_text("rule a { condition: true }")
    subdir = empty_dir / "malware"
    subdir.mkdir()
    (subdir / "sub.yara").write_text("rule b { condition: true }")

    result = cmd._list_yara_rules(yara_path=str(empty_dir))
    assert result == 0
    out = capsys.readouterr().out
    assert "Available YARA Rules" in out
    assert "root.yar" in out
    assert "sub.yara" in out


def test_config_command_helpers(tmp_path: Path):
    cmd = ConfigCommand(CommandContext.create())
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text("rule a { condition: true }")
    (rules_dir / "b.yara").write_text("rule b { condition: true }")

    rules = cmd._find_yara_rules(rules_dir)
    assert [p.name for p in rules] == ["a.yar", "b.yara"]

    assert cmd._format_file_size(10) == "10.0 B"
    assert cmd._format_file_size(1024) == "1.0 KB"


def test_validate_file_input_errors(tmp_path: Path):
    errors = validate_file_input(str(tmp_path))
    assert any("regular file" in e for e in errors)

    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    errors = validate_file_input(str(empty_file))
    assert any("File is empty" in e for e in errors)

    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"")
    os.truncate(large_file, 1024 * 1024 * 1024 + 1)
    errors = validate_file_input(str(large_file))
    assert any("File too large" in e for e in errors)


def test_validate_batch_input_errors(tmp_path: Path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("data")
    errors = validate_batch_input(str(file_path))
    assert any("not a directory" in e for e in errors)


def test_validate_output_input_permission_error(tmp_path: Path):
    output_path = tmp_path / "out.txt"
    output_path.write_text("data")
    os.chmod(output_path, 0o400)
    try:
        errors = validate_output_input(str(output_path))
        assert any("Cannot write" in e for e in errors)
    finally:
        os.chmod(output_path, 0o600)


def test_validate_yara_and_config_inputs(tmp_path: Path):
    errors = validate_yara_input(str(tmp_path / "missing"))
    assert any("does not exist" in e for e in errors)

    file_path = tmp_path / "file.yar"
    file_path.write_text("rule a { condition: true }")
    errors = validate_yara_input(str(file_path))
    assert any("not a directory" in e for e in errors)

    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    errors = validate_config_input(str(config_dir))
    assert any("not a file" in e for e in errors)

    config_file = tmp_path / "cfg.txt"
    config_file.write_text("{}")
    errors = validate_config_input(str(config_file))
    assert any("must be JSON" in e for e in errors)

    errors = validate_config_input(str(tmp_path / "missing.json"))
    assert any("does not exist" in e for e in errors)


def test_validate_extensions_threads_and_modes(tmp_path: Path):
    errors = validate_extensions_input(".ok, bad$ext")
    assert any("Invalid file extension" in e for e in errors)

    errors = validate_extensions_input(".toolongextension")
    assert any("too long" in e for e in errors)

    errors = validate_threads_input(0)
    assert any("positive integer" in e for e in errors)

    errors = validate_threads_input(51)
    assert any("Too many threads" in e for e in errors)

    with pytest.raises(SystemExit):
        validate_input_mode(None, None)

    with pytest.raises(SystemExit):
        validate_input_mode("file.bin", "batch")

    file_path = tmp_path / "file.bin"
    file_path.write_bytes(b"data")
    validate_input_mode(str(file_path), None)


def test_validate_single_file_and_xor_sanitization(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    with pytest.raises(SystemExit):
        validate_single_file(str(tmp_path / "missing.bin"))

    with pytest.raises(SystemExit):
        validate_single_file(str(tmp_path))

    assert sanitize_xor_string(None) is None
    assert sanitize_xor_string("abc$%") == "abc"

    long_input = "a" * 120
    assert sanitize_xor_string(long_input) == "a" * 100

    result = handle_xor_input("$$$")
    assert result is None
    out = capsys.readouterr().out
    assert "Warning" in out


def test_config_builder_variants():
    builder = (
        ConfigBuilder()
        .with_verbose(True)
        .with_max_strings(10)
        .with_string_length_range(3, 7)
        .with_yara_rules("rules")
        .with_yara_enabled(False)
        .with_yara_timeout(5)
        .with_packer_detection(False)
        .with_entropy_threshold(6.5)
        .with_section_analysis(False)
        .with_crypto_detection(False)
        .with_crypto_constants(False)
        .with_base64_detection(False)
        .with_string_min_length(5)
        .with_string_max_length(9)
        .with_unicode_extraction(False)
        .with_ascii_extraction(False)
        .with_json_indent(4)
        .with_csv_delimiter(";")
        .with_progress_display(False)
        .with_virustotal("key", enabled=True)
        .with_virustotal_timeout(9)
        .with_deep_analysis(True)
        .with_function_analysis(False)
        .with_graph_analysis(True)
        .with_authenticode_analysis(False)
        .with_overlay_analysis(False)
        .with_resource_analysis(False)
        .with_mitigation_analysis(False)
    )
    config = builder.build()
    assert config.general.verbose is True
    assert config.general.max_strings == 10
    assert config.general.min_string_length == 3
    assert config.general.max_string_length == 7
    assert config.yara.rules_path == "rules"
    assert config.yara.enabled is False
    assert config.yara.timeout == 5
    assert config.packer.enabled is False
    assert config.packer.entropy_threshold == 6.5
    assert config.packer.section_analysis is False
    assert config.crypto.enabled is False
    assert config.crypto.detect_constants is False
    assert config.crypto.detect_base64 is False
    assert config.strings.min_length == 5
    assert config.strings.max_length == 9
    assert config.strings.extract_unicode is False
    assert config.strings.extract_ascii is False
    assert config.output.json_indent == 4
    assert config.output.csv_delimiter == ";"
    assert config.output.show_progress is False
    assert config.virustotal.api_key == "key"
    assert config.virustotal.enabled is True
    assert config.virustotal.timeout == 9
    assert config.analysis.deep_analysis is True
    assert config.analysis.function_analysis is False
    assert config.analysis.graph_analysis is True
    assert config.pe_analysis.analyze_authenticode is False
    assert config.pe_analysis.analyze_overlay is False
    assert config.pe_analysis.analyze_resources is False
    assert config.pe_analysis.analyze_mitigations is False


def test_config_builder_shortcuts():
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
    assert full_cfg.analysis.function_analysis is True
    assert full_cfg.analysis.graph_analysis is True
    assert full_cfg.packer.enabled is True
    assert full_cfg.crypto.enabled is True
    assert full_cfg.yara.enabled is True
