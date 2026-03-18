"""Unit tests for domain/constants.py."""

from __future__ import annotations

from r2inspect.domain.constants import (
    EXCESSIVE_IMPORTS_THRESHOLD,
    FEW_IMPORTS_THRESHOLD,
    HIGH_ENTROPY_THRESHOLD,
    HUGE_FILE_THRESHOLD_MB,
    LARGE_FILE_THRESHOLD_MB,
    MAX_ENTROPY,
    MIN_EXECUTABLE_SIZE_BYTES,
    MIN_HEADER_SIZE_BYTES,
    MIN_INFO_RESPONSE_LENGTH,
    PACKING_EVIDENCE_THRESHOLD,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    VERY_LARGE_FILE_THRESHOLD_MB,
)


def test_file_validation_constants() -> None:
    assert MIN_EXECUTABLE_SIZE_BYTES == 32
    assert MIN_HEADER_SIZE_BYTES == 16
    assert MIN_INFO_RESPONSE_LENGTH == 10


def test_file_size_thresholds() -> None:
    assert LARGE_FILE_THRESHOLD_MB == 2
    assert VERY_LARGE_FILE_THRESHOLD_MB == 10
    assert HUGE_FILE_THRESHOLD_MB == 50
    assert LARGE_FILE_THRESHOLD_MB < VERY_LARGE_FILE_THRESHOLD_MB
    assert VERY_LARGE_FILE_THRESHOLD_MB < HUGE_FILE_THRESHOLD_MB


def test_entropy_constants() -> None:
    assert HIGH_ENTROPY_THRESHOLD == 7.0
    assert MAX_ENTROPY == 8.0
    assert HIGH_ENTROPY_THRESHOLD < MAX_ENTROPY


def test_risk_score_thresholds() -> None:
    assert RISK_CRITICAL == 80
    assert RISK_HIGH == 65
    assert RISK_MEDIUM == 45
    assert RISK_LOW == 25
    assert RISK_LOW < RISK_MEDIUM < RISK_HIGH < RISK_CRITICAL


def test_packing_detection_constants() -> None:
    assert PACKING_EVIDENCE_THRESHOLD == 50


def test_import_thresholds() -> None:
    assert FEW_IMPORTS_THRESHOLD == 10
    assert EXCESSIVE_IMPORTS_THRESHOLD == 500
    assert FEW_IMPORTS_THRESHOLD < EXCESSIVE_IMPORTS_THRESHOLD


def test_entropy_threshold_is_reasonable() -> None:
    assert 0 <= HIGH_ENTROPY_THRESHOLD <= MAX_ENTROPY


def test_min_executable_size_is_positive() -> None:
    assert MIN_EXECUTABLE_SIZE_BYTES > 0
    assert MIN_HEADER_SIZE_BYTES > 0


def test_risk_thresholds_form_ascending_order() -> None:
    thresholds = [RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL]
    assert thresholds == sorted(thresholds)
