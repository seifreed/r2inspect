"""
Unit tests for schemas, security validators, error handling, config schemas,
config, and config_store modules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# r2inspect/schemas/results_models.py
# ---------------------------------------------------------------------------

from r2inspect.schemas.results_models import (
    AnalysisResult,
    FileInfo,
    HashingResult,
    Indicator,
    PackerResult,
    AntiAnalysisResult,
    CryptoResult,
)


def test_file_info_defaults() -> None:
    fi = FileInfo()
    assert fi.name == ""
    assert fi.size == 0
    assert fi.sha256 == ""


def test_file_info_to_dict() -> None:
    fi = FileInfo(name="sample.exe", path="/tmp/sample.exe", size=1024, file_type="PE")
    d = fi.to_dict()
    assert d["name"] == "sample.exe"
    assert d["path"] == "/tmp/sample.exe"
    assert d["size"] == 1024
    assert d["file_type"] == "PE"


def test_analysis_result_defaults() -> None:
    ar = AnalysisResult()
    assert ar.error is None
    assert ar.execution_time == 0.0
    assert ar.imports == []
    assert ar.exports == []


def test_analysis_result_has_error() -> None:
    ar = AnalysisResult(error="something went wrong")
    assert ar.has_error() is True


def test_analysis_result_no_error() -> None:
    ar = AnalysisResult()
    assert ar.has_error() is False


def test_analysis_result_is_suspicious_packed() -> None:
    packer = PackerResult(is_packed=True, packer_type="UPX", confidence=90)
    ar = AnalysisResult(packer=packer)
    assert ar.is_suspicious() is True


def test_analysis_result_is_suspicious_evasion() -> None:
    anti = AntiAnalysisResult(anti_debug=True)
    ar = AnalysisResult(anti_analysis=anti)
    assert ar.is_suspicious() is True


def test_analysis_result_is_suspicious_indicators() -> None:
    ind = Indicator(type="Suspicious API", description="CreateRemoteThread", severity="High")
    ar = AnalysisResult(indicators=[ind])
    assert ar.is_suspicious() is True


def test_analysis_result_not_suspicious() -> None:
    ar = AnalysisResult()
    assert ar.is_suspicious() is False


def test_analysis_result_get_high_severity_indicators() -> None:
    low = Indicator(type="T", description="d", severity="Low")
    high = Indicator(type="T", description="d", severity="High")
    critical = Indicator(type="T", description="d", severity="Critical")
    ar = AnalysisResult(indicators=[low, high, critical])
    result = ar.get_high_severity_indicators()
    assert len(result) == 2
    severities = {i.severity for i in result}
    assert severities == {"High", "Critical"}


def test_analysis_result_to_dict_contains_keys() -> None:
    ar = AnalysisResult()
    d = ar.to_dict()
    for key in ("file_info", "hashing", "security", "imports", "exports", "timestamp"):
        assert key in d


def test_analysis_result_to_dict_timestamp_is_string() -> None:
    ar = AnalysisResult()
    d = ar.to_dict()
    assert isinstance(d["timestamp"], str)


def test_analysis_result_summary() -> None:
    ar = AnalysisResult()
    s = ar.summary()
    assert "file_name" in s
    assert "is_packed" in s
    assert "indicators_count" in s


def test_hashing_result_has_hash() -> None:
    hr = HashingResult(ssdeep="3:abc:def")
    assert hr.has_hash("ssdeep") is True
    assert hr.has_hash("tlsh") is False


def test_anti_analysis_has_evasion() -> None:
    aa = AntiAnalysisResult(anti_vm=True)
    assert aa.has_evasion() is True


def test_anti_analysis_no_evasion() -> None:
    aa = AntiAnalysisResult()
    assert aa.has_evasion() is False


def test_crypto_result_has_crypto() -> None:
    cr = CryptoResult(algorithms=[{"name": "AES"}])
    assert cr.has_crypto() is True


def test_crypto_result_no_crypto() -> None:
    cr = CryptoResult()
    assert cr.has_crypto() is False


# ---------------------------------------------------------------------------
# r2inspect/schemas/hashing.py
# ---------------------------------------------------------------------------

from r2inspect.schemas.hashing import HashAnalysisResult


def test_hash_analysis_result_valid() -> None:
    r = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value="3:a:b")
    assert r.hash_type == "ssdeep"
    assert r.is_valid_hash() is True


def test_hash_analysis_result_normalizes_hash_type() -> None:
    r = HashAnalysisResult(available=True, hash_type="TLSH")
    assert r.hash_type == "tlsh"


def test_hash_analysis_result_invalid_hash_type() -> None:
    with pytest.raises(Exception):
        HashAnalysisResult(available=True, hash_type="md5")


def test_hash_analysis_result_invalid_file_size() -> None:
    with pytest.raises(Exception):
        HashAnalysisResult(available=True, hash_type="ssdeep", file_size=-1)


def test_hash_analysis_result_none_hash_value() -> None:
    r = HashAnalysisResult(available=True, hash_type="tlsh", hash_value=None)
    assert r.is_valid_hash() is False


def test_hash_analysis_result_method_used_normalized() -> None:
    r = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="Python_Library")
    assert r.method_used == "python_library"


def test_hash_analysis_result_custom_method_allowed() -> None:
    r = HashAnalysisResult(available=True, hash_type="ssdeep", method_used="custom_tool")
    assert r.method_used == "custom_tool"


def test_hash_analysis_result_file_size_zero() -> None:
    r = HashAnalysisResult(available=True, hash_type="ssdeep", file_size=0)
    assert r.file_size == 0


# ---------------------------------------------------------------------------
# r2inspect/schemas/security.py
# ---------------------------------------------------------------------------

from r2inspect.schemas.security import (
    AuthenticodeAnalysisResult,
    MitigationInfo,
    SecurityAnalysisResult,
    SecurityGrade,
    SecurityIssue,
    SecurityScore,
    SeverityLevel,
)


def test_security_issue_valid() -> None:
    issue = SecurityIssue(severity=SeverityLevel.HIGH, description="No DEP")
    assert issue.severity == SeverityLevel.HIGH
    assert issue.description == "No DEP"


def test_security_issue_strips_description() -> None:
    issue = SecurityIssue(severity=SeverityLevel.LOW, description="  desc  ")
    assert issue.description == "desc"


def test_security_issue_empty_description_raises() -> None:
    with pytest.raises(Exception):
        SecurityIssue(severity=SeverityLevel.LOW, description="")


def test_security_issue_whitespace_only_description_raises() -> None:
    with pytest.raises(Exception):
        SecurityIssue(severity=SeverityLevel.LOW, description="   ")


def test_security_issue_cvss_valid() -> None:
    issue = SecurityIssue(severity=SeverityLevel.CRITICAL, description="CVE", cvss_score=9.8)
    assert issue.cvss_score == 9.8


def test_security_issue_cvss_out_of_range_raises() -> None:
    with pytest.raises(Exception):
        SecurityIssue(severity=SeverityLevel.LOW, description="d", cvss_score=11.0)


def test_security_issue_cwe_id_valid() -> None:
    issue = SecurityIssue(severity=SeverityLevel.MEDIUM, description="d", cwe_id=22)
    assert issue.cwe_id == 22


def test_security_issue_cwe_id_zero_raises() -> None:
    with pytest.raises(Exception):
        SecurityIssue(severity=SeverityLevel.LOW, description="d", cwe_id=0)


def test_mitigation_info_enabled() -> None:
    m = MitigationInfo(enabled=True, description="ASLR enabled")
    assert m.enabled is True


def test_mitigation_info_disabled() -> None:
    m = MitigationInfo(enabled=False, description="DEP missing")
    assert m.enabled is False


def test_security_score_valid() -> None:
    ss = SecurityScore(score=70, max_score=100, percentage=70.0, grade=SecurityGrade.B)
    assert ss.score == 70
    assert ss.grade == SecurityGrade.B


def test_security_score_max_less_than_score_raises() -> None:
    with pytest.raises(Exception):
        SecurityScore(score=90, max_score=80, percentage=90.0, grade=SecurityGrade.A)


def test_security_analysis_result_empty() -> None:
    r = SecurityAnalysisResult(available=True)
    assert r.issues == []
    assert r.mitigations == {}
    assert r.features == {}


def test_security_analysis_result_get_critical_issues() -> None:
    crit = SecurityIssue(severity=SeverityLevel.CRITICAL, description="crit")
    low = SecurityIssue(severity=SeverityLevel.LOW, description="low")
    r = SecurityAnalysisResult(available=True, issues=[crit, low])
    assert len(r.get_critical_issues()) == 1
    assert r.get_critical_issues()[0].description == "crit"


def test_security_analysis_result_get_high_issues() -> None:
    high = SecurityIssue(severity=SeverityLevel.HIGH, description="high")
    r = SecurityAnalysisResult(available=True, issues=[high])
    assert len(r.get_high_issues()) == 1


def test_security_analysis_result_get_enabled_mitigations() -> None:
    r = SecurityAnalysisResult(
        available=True,
        mitigations={
            "aslr": MitigationInfo(enabled=True, description="ASLR"),
            "dep": MitigationInfo(enabled=False, description="DEP"),
        },
    )
    enabled = r.get_enabled_mitigations()
    assert "aslr" in enabled
    assert "dep" not in enabled


def test_security_analysis_result_get_disabled_mitigations() -> None:
    r = SecurityAnalysisResult(
        available=True,
        mitigations={
            "aslr": MitigationInfo(enabled=True, description="ASLR"),
            "dep": MitigationInfo(enabled=False, description="DEP"),
        },
    )
    disabled = r.get_disabled_mitigations()
    assert "dep" in disabled
    assert "aslr" not in disabled


def test_security_analysis_result_has_mitigation() -> None:
    r = SecurityAnalysisResult(
        available=True,
        mitigations={"nx": MitigationInfo(enabled=True, description="NX")},
    )
    assert r.has_mitigation("nx") is True
    assert r.has_mitigation("aslr") is False


def test_security_analysis_result_count_issues_by_severity() -> None:
    issues = [
        SecurityIssue(severity=SeverityLevel.HIGH, description="h1"),
        SecurityIssue(severity=SeverityLevel.HIGH, description="h2"),
        SecurityIssue(severity=SeverityLevel.LOW, description="l1"),
    ]
    r = SecurityAnalysisResult(available=True, issues=issues)
    counts = r.count_issues_by_severity()
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0


def test_security_analysis_result_is_secure() -> None:
    r = SecurityAnalysisResult(available=True, score=80)
    assert r.is_secure() is True


def test_security_analysis_result_is_not_secure() -> None:
    r = SecurityAnalysisResult(available=True, score=50)
    assert r.is_secure() is False


def test_security_analysis_result_is_secure_no_score() -> None:
    r = SecurityAnalysisResult(available=True)
    assert r.is_secure() is False


def test_security_analysis_result_score_out_of_range_raises() -> None:
    with pytest.raises(Exception):
        SecurityAnalysisResult(available=True, score=150)


def test_authenticode_analysis_result_unsigned() -> None:
    r = AuthenticodeAnalysisResult(available=True, signed=False)
    assert r.signed is False
    assert r.valid is None
    assert r.signer is None


def test_authenticode_analysis_result_signed() -> None:
    r = AuthenticodeAnalysisResult(
        available=True,
        signed=True,
        valid=True,
        signer="Microsoft Corp",
        signature_algorithm="sha256",
    )
    assert r.signed is True
    assert r.valid is True
    assert r.signer == "Microsoft Corp"


# ---------------------------------------------------------------------------
# r2inspect/security/validators.py
# ---------------------------------------------------------------------------

from r2inspect.security.validators import FileValidator, validate_file_for_analysis


def test_file_validator_valid_path(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 100)
    validator = FileValidator()
    resolved = validator.validate_path(str(f))
    assert resolved == f.resolve()


def test_file_validator_nonexistent_raises() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_path("/nonexistent/path/file.bin")


def test_file_validator_empty_path_raises() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_path("")


def test_file_validator_null_byte_raises() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_path("/tmp/file\x00name")


def test_file_validator_dangerous_chars_raises() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_path("/tmp/file;rm -rf /")


def test_file_validator_too_long_path_raises() -> None:
    validator = FileValidator()
    long_path = "/tmp/" + "a" * 5000
    with pytest.raises(ValueError):
        validator.validate_path(long_path)


def test_file_validator_allowed_directory_valid(tmp_path: Path) -> None:
    f = tmp_path / "file.bin"
    f.write_bytes(b"\xFF" * 50)
    validator = FileValidator(allowed_directory=tmp_path)
    resolved = validator.validate_path(str(f))
    assert resolved.parent == tmp_path.resolve()


def test_file_validator_outside_allowed_directory_raises(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    f = tmp_path / "outside.bin"
    f.write_bytes(b"\xFF" * 50)
    validator = FileValidator(allowed_directory=allowed)
    with pytest.raises(ValueError, match="outside allowed directory"):
        validator.validate_path(str(f))


def test_file_validator_check_exists_false(tmp_path: Path) -> None:
    nonexistent = tmp_path / "ghost.bin"
    validator = FileValidator()
    resolved = validator.validate_path(str(nonexistent), check_exists=False)
    assert resolved is not None


def test_file_validator_sanitize_for_subprocess(tmp_path: Path) -> None:
    f = tmp_path / "clean.bin"
    f.write_bytes(b"\x00" * 10)
    validator = FileValidator()
    resolved = validator.validate_path(str(f))
    safe = validator.sanitize_for_subprocess(resolved)
    assert isinstance(safe, str)
    assert str(f.resolve()) == safe


def test_file_validator_sanitize_non_path_raises() -> None:
    validator = FileValidator()
    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("/tmp/not_a_path_object")  # type: ignore[arg-type]


def test_file_validator_invalid_allowed_directory_raises() -> None:
    with pytest.raises(ValueError):
        FileValidator(allowed_directory=Path("/nonexistent/directory/xyz"))


def test_validate_file_for_analysis_valid(tmp_path: Path) -> None:
    f = tmp_path / "test.bin"
    f.write_bytes(b"\xDE\xAD\xBE\xEF" * 10)
    result = validate_file_for_analysis(str(f))
    assert result == f.resolve()


def test_validate_file_for_analysis_empty_file_raises(tmp_path: Path) -> None:
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        validate_file_for_analysis(str(f))


def test_validate_file_for_analysis_too_large_raises(tmp_path: Path) -> None:
    f = tmp_path / "big.bin"
    f.write_bytes(b"\x00" * 100)
    with pytest.raises(ValueError, match="too large"):
        validate_file_for_analysis(str(f), max_size=10)


def test_file_validator_yara_content_valid() -> None:
    validator = FileValidator()
    content = 'rule test { strings: $a = "hello" condition: $a }'
    validator.validate_yara_rule_content(content)  # should not raise


def test_file_validator_yara_content_empty_raises() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("")


def test_file_validator_yara_content_include_raises() -> None:
    validator = FileValidator()
    content = 'include "evil_rules.yar"\nrule test { condition: true }'
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content(content)


# ---------------------------------------------------------------------------
# r2inspect/error_handling/policies.py
# ---------------------------------------------------------------------------

from r2inspect.error_handling.policies import ErrorHandlingStrategy, ErrorPolicy


def test_error_policy_defaults() -> None:
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FAIL_FAST)
    assert policy.max_retries == 3
    assert policy.retry_delay == 1.0
    assert policy.retry_backoff == 2.0
    assert policy.retry_jitter is True


def test_error_policy_negative_retries_raises() -> None:
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, max_retries=-1)


def test_error_policy_negative_delay_raises() -> None:
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, retry_delay=-0.1)


def test_error_policy_backoff_less_than_one_raises() -> None:
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, retry_backoff=0.5)


def test_error_policy_circuit_threshold_zero_raises() -> None:
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.CIRCUIT_BREAK, circuit_threshold=0)


def test_error_policy_circuit_timeout_negative_raises() -> None:
    with pytest.raises(ValueError):
        ErrorPolicy(strategy=ErrorHandlingStrategy.CIRCUIT_BREAK, circuit_timeout=-1)


def test_error_policy_is_retryable_matching_exception() -> None:
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retryable_exceptions={ConnectionError},
    )
    assert policy.is_retryable(ConnectionError("fail")) is True


def test_error_policy_is_retryable_fatal_exception() -> None:
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retryable_exceptions={Exception},
        fatal_exceptions={MemoryError},
    )
    assert policy.is_retryable(MemoryError()) is False


def test_error_policy_is_retryable_unmatched_exception() -> None:
    policy = ErrorPolicy(
        strategy=ErrorHandlingStrategy.RETRY,
        retryable_exceptions={ConnectionError},
    )
    assert policy.is_retryable(ValueError("nope")) is False


def test_error_policy_copy_with_overrides() -> None:
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, max_retries=3)
    new_policy = policy.copy_with_overrides(max_retries=5)
    assert new_policy.max_retries == 5
    assert policy.max_retries == 3  # original unchanged


def test_error_policy_copy_with_overrides_invalid_attr_raises() -> None:
    policy = ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY)
    with pytest.raises(AttributeError):
        policy.copy_with_overrides(nonexistent_attr=42)


# ---------------------------------------------------------------------------
# r2inspect/error_handling/presets.py
# ---------------------------------------------------------------------------

from r2inspect.error_handling.presets import (
    AGGRESSIVE_RETRY_POLICY,
    CIRCUIT_BREAK_POLICY,
    FAIL_FAST_POLICY,
    FALLBACK_LIST_POLICY,
    FALLBACK_NONE_POLICY,
    FALLBACK_STRING_POLICY,
    GENTLE_RETRY_POLICY,
    R2_JSON_DICT_POLICY,
    R2_JSON_LIST_POLICY,
    R2_TEXT_POLICY,
    RETRY_POLICY,
    SAFE_POLICY,
    STRICT_CIRCUIT_POLICY,
    TOLERANT_CIRCUIT_POLICY,
    create_custom_policy,
)


def test_fail_fast_policy_strategy() -> None:
    assert FAIL_FAST_POLICY.strategy == ErrorHandlingStrategy.FAIL_FAST


def test_retry_policy_strategy() -> None:
    assert RETRY_POLICY.strategy == ErrorHandlingStrategy.RETRY
    assert RETRY_POLICY.max_retries == 3


def test_aggressive_retry_policy() -> None:
    assert AGGRESSIVE_RETRY_POLICY.max_retries == 5
    assert AGGRESSIVE_RETRY_POLICY.retry_delay < RETRY_POLICY.retry_delay


def test_gentle_retry_policy() -> None:
    assert GENTLE_RETRY_POLICY.max_retries == 2


def test_safe_policy_fallback_value() -> None:
    assert SAFE_POLICY.fallback_value == {}
    assert SAFE_POLICY.strategy == ErrorHandlingStrategy.FALLBACK


def test_fallback_list_policy() -> None:
    assert FALLBACK_LIST_POLICY.fallback_value == []


def test_fallback_none_policy() -> None:
    assert FALLBACK_NONE_POLICY.fallback_value is None


def test_fallback_string_policy() -> None:
    assert FALLBACK_STRING_POLICY.fallback_value == ""


def test_circuit_break_policy_strategy() -> None:
    assert CIRCUIT_BREAK_POLICY.strategy == ErrorHandlingStrategy.CIRCUIT_BREAK
    assert CIRCUIT_BREAK_POLICY.circuit_threshold == 5


def test_strict_circuit_policy() -> None:
    assert STRICT_CIRCUIT_POLICY.circuit_threshold == 3
    assert STRICT_CIRCUIT_POLICY.circuit_timeout == 30


def test_tolerant_circuit_policy() -> None:
    assert TOLERANT_CIRCUIT_POLICY.circuit_threshold == 10
    assert TOLERANT_CIRCUIT_POLICY.circuit_timeout == 120


def test_r2_json_dict_policy() -> None:
    assert R2_JSON_DICT_POLICY.fallback_value == {}


def test_r2_json_list_policy() -> None:
    assert R2_JSON_LIST_POLICY.fallback_value == []


def test_r2_text_policy() -> None:
    assert R2_TEXT_POLICY.fallback_value == ""


def test_create_custom_policy_retry() -> None:
    policy = create_custom_policy(ErrorHandlingStrategy.RETRY, max_retries=7)
    assert policy.strategy == ErrorHandlingStrategy.RETRY
    assert policy.max_retries == 7


def test_create_custom_policy_fallback_value() -> None:
    policy = create_custom_policy(ErrorHandlingStrategy.FALLBACK, fallback_value={"result": []})
    assert policy.fallback_value == {"result": []}


# ---------------------------------------------------------------------------
# r2inspect/error_handling/stats.py
# ---------------------------------------------------------------------------

from r2inspect.error_handling.stats import get_error_stats_snapshot


def test_get_error_stats_snapshot_keys() -> None:
    snapshot = get_error_stats_snapshot()
    assert "error_stats" in snapshot
    assert "retry_stats" in snapshot
    assert "circuit_breaker_stats" in snapshot


def test_get_error_stats_snapshot_returns_dict() -> None:
    snapshot = get_error_stats_snapshot()
    assert isinstance(snapshot, dict)


# ---------------------------------------------------------------------------
# r2inspect/config_schemas/schemas.py
# ---------------------------------------------------------------------------

from r2inspect.config_schemas.schemas import (
    GeneralConfig,
    PackerConfig,
    R2InspectConfig,
    YaraConfig,
)


def test_general_config_defaults() -> None:
    gc = GeneralConfig()
    assert gc.verbose is False
    assert gc.max_strings == 1000
    assert gc.min_string_length == 4


def test_general_config_negative_max_strings_raises() -> None:
    with pytest.raises(ValueError):
        GeneralConfig(max_strings=-1)


def test_general_config_min_string_length_zero_raises() -> None:
    with pytest.raises(ValueError):
        GeneralConfig(min_string_length=0)


def test_general_config_max_less_than_min_raises() -> None:
    with pytest.raises(ValueError):
        GeneralConfig(min_string_length=50, max_string_length=10)


def test_yara_config_defaults() -> None:
    yc = YaraConfig()
    assert yc.enabled is True
    assert yc.timeout == 60
    assert yc.rules_path == "rules/yara"


def test_yara_config_timeout_zero_raises() -> None:
    with pytest.raises(ValueError):
        YaraConfig(timeout=0)


def test_packer_config_defaults() -> None:
    pc = PackerConfig()
    assert pc.enabled is True
    assert pc.entropy_threshold == 7.0


def test_packer_config_entropy_out_of_range_raises() -> None:
    with pytest.raises(ValueError):
        PackerConfig(entropy_threshold=9.0)


def test_packer_config_entropy_negative_raises() -> None:
    with pytest.raises(ValueError):
        PackerConfig(entropy_threshold=-1.0)


def test_r2inspect_config_defaults() -> None:
    cfg = R2InspectConfig()
    assert cfg.general.verbose is False
    assert cfg.yara.enabled is True
    assert cfg.packer.enabled is True


def test_r2inspect_config_to_dict() -> None:
    cfg = R2InspectConfig()
    d = cfg.to_dict()
    assert "general" in d
    assert "yara" in d
    assert "packer" in d
    assert "virustotal" in d


def test_r2inspect_config_from_dict_roundtrip() -> None:
    cfg = R2InspectConfig()
    d = cfg.to_dict()
    cfg2 = R2InspectConfig.from_dict(d)
    assert cfg2.general.verbose == cfg.general.verbose
    assert cfg2.yara.timeout == cfg.yara.timeout


def test_r2inspect_config_from_dict_partial() -> None:
    cfg = R2InspectConfig.from_dict({"general": {"verbose": True}})
    assert cfg.general.verbose is True


def test_r2inspect_config_from_dict_non_dict_raises() -> None:
    with pytest.raises(TypeError):
        R2InspectConfig.from_dict("not a dict")  # type: ignore[arg-type]


def test_r2inspect_config_merge() -> None:
    cfg1 = R2InspectConfig()
    cfg2 = R2InspectConfig.from_dict({"general": {"verbose": True}})
    merged = cfg1.merge(cfg2)
    assert merged.general.verbose is True


def test_r2inspect_config_frozen() -> None:
    cfg = R2InspectConfig()
    with pytest.raises((AttributeError, TypeError)):
        cfg.general = GeneralConfig(verbose=True)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# r2inspect/config.py
# ---------------------------------------------------------------------------

from r2inspect.config import Config


def test_config_init_creates_file(tmp_path: Path) -> None:
    cfg_path = str(tmp_path / "config.json")
    cfg = Config(config_path=cfg_path)
    assert Path(cfg_path).exists()
    assert cfg.typed_config is not None


def test_config_defaults_are_sane(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    assert cfg.typed_config.general.verbose is False
    assert cfg.typed_config.yara.enabled is True


def test_config_set_and_get(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    cfg.set("general", "verbose", True)
    assert cfg.typed_config.general.verbose is True


def test_config_to_dict_has_all_sections(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    d = cfg.to_dict()
    for section in ("general", "yara", "packer", "crypto", "output", "virustotal"):
        assert section in d


def test_config_save_and_load(tmp_path: Path) -> None:
    cfg_path = str(tmp_path / "config.json")
    cfg = Config(config_path=cfg_path)
    cfg.set("general", "verbose", True)
    cfg.save_config()
    # Reload from disk
    cfg2 = Config(config_path=cfg_path)
    assert cfg2.typed_config.general.verbose is True


def test_config_load_corrupted_falls_back_to_defaults(tmp_path: Path) -> None:
    cfg_path = str(tmp_path / "bad.json")
    Path(cfg_path).write_text("not valid json")
    cfg = Config(config_path=cfg_path)
    # Should fall back to defaults without raising
    assert cfg.typed_config.general.max_strings == 1000


def test_config_apply_overrides(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    cfg.apply_overrides({"general": {"verbose": True, "max_strings": 500}})
    assert cfg.typed_config.general.verbose is True
    assert cfg.typed_config.general.max_strings == 500


def test_config_from_dict(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    new_cfg = cfg.from_dict({"general": {"verbose": True}})
    assert new_cfg.typed_config.general.verbose is True


def test_config_get_yara_rules_path_absolute(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    cfg = Config(config_path=str(tmp_path / "config.json"))
    cfg.set("yara", "rules_path", str(rules_dir))
    path = cfg.get_yara_rules_path()
    assert path == str(rules_dir)


def test_config_is_virustotal_disabled_by_default(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    assert cfg.is_virustotal_enabled() is False


def test_config_get_virustotal_api_key_empty(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    assert cfg.get_virustotal_api_key() == ""


def test_config_pe_analysis_properties(tmp_path: Path) -> None:
    cfg = Config(config_path=str(tmp_path / "config.json"))
    assert cfg.analyze_authenticode is True
    assert cfg.analyze_overlay is True
    assert cfg.analyze_resources is True
    assert cfg.analyze_mitigations is True


# ---------------------------------------------------------------------------
# r2inspect/config_store.py
# ---------------------------------------------------------------------------

from r2inspect.config_store import ConfigStore


def test_config_store_save_and_load(tmp_path: Path) -> None:
    path = str(tmp_path / "store.json")
    payload = {"key": "value", "nested": {"a": 1}}
    ConfigStore.save(path, payload)
    loaded = ConfigStore.load(path)
    assert loaded == payload


def test_config_store_load_nonexistent_returns_none(tmp_path: Path) -> None:
    result = ConfigStore.load(str(tmp_path / "missing.json"))
    assert result is None


def test_config_store_load_invalid_json_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ invalid json")
    result = ConfigStore.load(str(path))
    assert result is None


def test_config_store_save_creates_one_level_parent(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    # ConfigStore.save creates one level of parent dir via mkdir(exist_ok=True)
    path = str(sub / "config.json")
    ConfigStore.save(path, {"x": 1})
    assert Path(path).exists()
    loaded = ConfigStore.load(path)
    assert loaded == {"x": 1}


def test_config_store_load_non_dict_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2, 3]))
    result = ConfigStore.load(str(path))
    assert result is None


def test_config_store_save_pretty_printed(tmp_path: Path) -> None:
    path = str(tmp_path / "pretty.json")
    ConfigStore.save(path, {"a": 1})
    content = Path(path).read_text()
    assert "\n" in content  # indent=2 produces newlines
