from __future__ import annotations

import pytest

from r2inspect.utils import error_handler as eh


def test_error_classifier_context_adjustments() -> None:
    info = eh.ErrorClassifier.classify(ValueError("bad"), {"analysis_type": "pe_analysis"})
    assert info.category == eh.ErrorCategory.INPUT_VALIDATION
    assert info.severity == eh.ErrorSeverity.HIGH

    info = eh.ErrorClassifier.classify(
        ValueError("bad"),
        {"analysis_type": "pe_analysis", "batch_mode": True},
    )
    assert info.severity == eh.ErrorSeverity.MEDIUM

    info = eh.ErrorClassifier.classify(MemoryError("oom"), {"file_size_mb": 200})
    assert info.category == eh.ErrorCategory.MEMORY
    assert info.severity == eh.ErrorSeverity.HIGH

    info = eh.ErrorClassifier.classify(Exception("r2pipe failure"), {})
    assert info.category == eh.ErrorCategory.R2PIPE


def test_error_recovery_manager_and_stats() -> None:
    manager = eh.ErrorRecoveryManager()

    info = eh.ErrorInfo(
        exception=ValueError("bad"),
        severity=eh.ErrorSeverity.MEDIUM,
        category=eh.ErrorCategory.INPUT_VALIDATION,
    )
    recovered, result = manager.handle_error(info)
    assert recovered is False
    assert result is None

    def recover(_info: eh.ErrorInfo) -> str:
        return "ok"

    manager.register_recovery_strategy(eh.ErrorCategory.INPUT_VALIDATION, recover)
    recovered, result = manager.handle_error(info)
    assert recovered is True
    assert result == "ok"

    stats = manager.get_error_stats()
    assert stats["total_errors"] >= 2


def test_error_handler_decorator_and_safe_execute() -> None:
    eh.reset_error_stats()

    @eh.error_handler(
        category=eh.ErrorCategory.FILE_ACCESS,
        severity=eh.ErrorSeverity.HIGH,
        fallback_result="fallback",
    )
    def missing_file() -> str:
        raise FileNotFoundError("missing")

    assert missing_file() is None

    @eh.error_handler()
    def crash() -> None:
        raise MemoryError("boom")

    with pytest.raises(MemoryError):
        crash()

    def r2pipe_fail() -> None:
        raise RuntimeError("r2pipe failed")

    assert eh.safe_execute(r2pipe_fail, context={"command": "ij"}) is None

    def bad_input() -> None:
        raise ValueError("bad input")

    assert eh.safe_execute(bad_input, fallback_result="fallback") == "fallback"
