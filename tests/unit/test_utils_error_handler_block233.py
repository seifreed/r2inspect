from __future__ import annotations

import pytest

from r2inspect.utils import error_handler as eh


def test_error_classifier_basic() -> None:
    info = eh.ErrorClassifier.classify(ValueError("bad"), {"analysis_type": "pe_analysis"})
    assert info.category == eh.ErrorCategory.INPUT_VALIDATION
    assert info.severity == eh.ErrorSeverity.HIGH
    assert info.recoverable is True
    assert "Validate input" in info.suggested_action

    info = eh.ErrorClassifier.classify(MemoryError("oom"), {"file_size_mb": 200})
    assert info.category == eh.ErrorCategory.MEMORY
    assert info.severity == eh.ErrorSeverity.HIGH
    assert info.recoverable is True

    info = eh.ErrorClassifier.classify(PermissionError("nope"), {"component_optional": False})
    assert info.category == eh.ErrorCategory.FILE_ACCESS
    assert info.recoverable is False

    class FakeR2Error(Exception):
        pass

    info = eh.ErrorClassifier.classify(FakeR2Error("r2pipe failed"), {"phase": "initialization"})
    assert info.category == eh.ErrorCategory.R2PIPE
    assert info.severity == eh.ErrorSeverity.CRITICAL


def test_error_recovery_manager_strategies() -> None:
    manager = eh.ErrorRecoveryManager()

    def strategy(info: eh.ErrorInfo) -> str:
        return "ok"

    manager.register_recovery_strategy(eh.ErrorCategory.INPUT_VALIDATION, strategy)

    error_info = eh.ErrorInfo(
        ValueError("bad"), eh.ErrorSeverity.MEDIUM, eh.ErrorCategory.INPUT_VALIDATION
    )
    recovered, result = manager.handle_error(error_info)
    assert recovered is True
    assert result == "ok"

    def broken_strategy(info: eh.ErrorInfo) -> str:
        raise RuntimeError("fail")

    manager.register_recovery_strategy(eh.ErrorCategory.NETWORK, broken_strategy)
    error_info = eh.ErrorInfo(
        ConnectionError("net"), eh.ErrorSeverity.MEDIUM, eh.ErrorCategory.NETWORK
    )
    recovered, result = manager.handle_error(error_info)
    assert recovered is False
    assert result is None


def test_error_handler_decorator_and_safe_execute() -> None:
    eh.reset_error_stats()

    @eh.error_handler(
        category=eh.ErrorCategory.R2PIPE,
        severity=eh.ErrorSeverity.MEDIUM,
        context={"command": "aa"},
        fallback_result="fallback",
    )
    def will_fail() -> str:
        raise RuntimeError("boom")

    assert will_fail() == ""

    @eh.error_handler(
        category=eh.ErrorCategory.ANALYSIS,
        severity=eh.ErrorSeverity.CRITICAL,
    )
    def critical_fail() -> None:
        raise MemoryError("oom")

    with pytest.raises(MemoryError):
        critical_fail()

    def plain_fail() -> str:
        raise ValueError("bad")

    assert eh.safe_execute(plain_fail, fallback_result="fallback") == "fallback"

    def ok() -> str:
        return "ok"

    assert eh.safe_execute(ok) == "ok"


def test_global_error_stats() -> None:
    eh.reset_error_stats()
    stats = eh.get_error_stats()
    assert stats["total_errors"] == 0

    def fail() -> None:
        raise ValueError("bad")

    eh.safe_execute(fail, fallback_result=None)
    stats = eh.get_error_stats()
    assert stats["total_errors"] >= 1
