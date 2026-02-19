from __future__ import annotations

from r2inspect.modules.security_scoring import _grade_from_percentage, build_security_score
from r2inspect.modules.string_extraction import (
    extract_ascii_from_bytes,
    extract_strings_from_entries,
    split_null_terminated,
)


# ----- security_scoring tests -----

def _make_result(mitigations: dict | None = None, vulnerabilities: list | None = None) -> dict:
    return {
        "mitigations": mitigations or {},
        "vulnerabilities": vulnerabilities or [],
    }


def test_build_security_score_no_enabled_mitigations() -> None:
    result = _make_result()
    score = build_security_score(result)
    assert score["score"] == 0
    assert score["max_score"] > 0
    assert score["percentage"] == 0.0
    assert score["grade"] == "F"


def test_build_security_score_with_enabled_mitigations() -> None:
    result = _make_result(
        mitigations={
            "ASLR": {"enabled": True, "high_entropy": False},
            "DEP": {"enabled": True},
        }
    )
    score = build_security_score(result)
    assert score["score"] > 0
    assert score["max_score"] > 0
    assert score["percentage"] > 0.0


def test_build_security_score_with_aslr_high_entropy() -> None:
    result = _make_result(
        mitigations={
            "ASLR": {"enabled": True, "high_entropy": True},
        }
    )
    score = build_security_score(result)
    assert score["score"] == 20


def test_build_security_score_high_vulnerability_reduces_score() -> None:
    result = _make_result(
        mitigations={
            "ASLR": {"enabled": True, "high_entropy": False},
            "DEP": {"enabled": True},
        },
        vulnerabilities=[{"severity": "high"}, {"severity": "medium"}],
    )
    score = build_security_score(result)
    assert score["score"] >= 0


def test_build_security_score_score_clamped_to_zero() -> None:
    result = _make_result(
        mitigations={},
        vulnerabilities=[{"severity": "high"} for _ in range(10)],
    )
    score = build_security_score(result)
    assert score["score"] == 0


def test_grade_from_percentage_unknown_when_max_zero() -> None:
    assert _grade_from_percentage(0.0, 0) == "Unknown"


def test_grade_from_percentage_a_at_90() -> None:
    assert _grade_from_percentage(90.0, 100) == "A"


def test_grade_from_percentage_b_at_80() -> None:
    assert _grade_from_percentage(80.0, 100) == "B"


def test_grade_from_percentage_c_at_70() -> None:
    assert _grade_from_percentage(70.0, 100) == "C"


def test_grade_from_percentage_d_at_60() -> None:
    assert _grade_from_percentage(60.0, 100) == "D"


def test_grade_from_percentage_f_below_60() -> None:
    assert _grade_from_percentage(59.9, 100) == "F"
    assert _grade_from_percentage(0.0, 100) == "F"


# ----- string_extraction tests -----

def test_extract_strings_from_entries_none_returns_empty() -> None:
    assert extract_strings_from_entries(None, 4) == []


def test_extract_strings_from_entries_empty_list_returns_empty() -> None:
    assert extract_strings_from_entries([], 4) == []


def test_extract_strings_from_entries_filters_by_min_length() -> None:
    entries = [
        {"string": "hi"},
        {"string": "hello"},
        {"string": "world"},
    ]
    result = extract_strings_from_entries(entries, 4)
    assert "hi" not in result
    assert "hello" in result
    assert "world" in result


def test_extract_strings_from_entries_skips_missing_string_key() -> None:
    entries = [{"type": "ascii"}, {"string": "valid_string"}]
    result = extract_strings_from_entries(entries, 4)
    assert "valid_string" in result
    assert len(result) == 1


def test_extract_ascii_from_bytes_basic() -> None:
    data = [ord(c) for c in "hello world"] + [0x00]
    result = extract_ascii_from_bytes(data, min_length=4)
    assert "hello world" in result


def test_extract_ascii_from_bytes_respects_limit() -> None:
    data = []
    for i in range(20):
        data.extend([ord(c) for c in f"string{i:03d}"] + [0x00])
    result = extract_ascii_from_bytes(data, min_length=4, limit=5)
    assert len(result) <= 5


def test_extract_ascii_from_bytes_skips_non_printable() -> None:
    data = [ord("a"), ord("b"), 0x01, ord("c"), ord("d"), ord("e"), ord("f")]
    result = extract_ascii_from_bytes(data, min_length=4)
    assert "cdef" in result
    assert "ab" not in result


def test_extract_ascii_from_bytes_trailing_string() -> None:
    data = [ord(c) for c in "test"]
    result = extract_ascii_from_bytes(data, min_length=4)
    assert "test" in result


def test_extract_ascii_from_bytes_invalid_values_skipped() -> None:
    data = [65, "bad", None, 66, 67, 68, 69]
    result = extract_ascii_from_bytes(data, min_length=4)
    assert isinstance(result, list)


def test_split_null_terminated_basic() -> None:
    result = split_null_terminated("hello\0world\0test", min_length=4)
    assert "hello" in result
    assert "world" in result
    assert "test" in result


def test_split_null_terminated_empty_returns_empty() -> None:
    assert split_null_terminated("", min_length=4) == []
    assert split_null_terminated(None, min_length=4) == []  # type: ignore


def test_split_null_terminated_filters_short_parts() -> None:
    result = split_null_terminated("hi\0hello\0world", min_length=4)
    assert "hi" not in result
    assert "hello" in result


def test_split_null_terminated_respects_limit() -> None:
    text = "\0".join([f"string{i:03d}" for i in range(20)])
    result = split_null_terminated(text, min_length=4, limit=5)
    assert len(result) <= 5
