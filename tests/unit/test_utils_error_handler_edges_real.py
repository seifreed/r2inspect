from __future__ import annotations

from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorClassifier,
    ErrorRecoveryManager,
    ErrorSeverity,
    error_handler,
    safe_execute,
)


def test_error_classifier_adjustments_and_actions() -> None:
    info = ErrorClassifier.classify(ValueError("bad"), {"analysis_type": "pe_analysis"})
    assert info.severity == ErrorSeverity.HIGH

    info = ErrorClassifier.classify(FileNotFoundError("missing"), {"batch_mode": True})
    assert info.severity == ErrorSeverity.MEDIUM
    assert "Skip this component" in info.suggested_action

    info = ErrorClassifier.classify(MemoryError("mem"), {"file_size_mb": 200})
    assert info.severity == ErrorSeverity.HIGH
    assert "garbage" in info.suggested_action.lower()

    info = ErrorClassifier.classify(RuntimeError("r2pipe failed"), {"phase": "initialization"})
    assert info.category == ErrorCategory.R2PIPE
    assert info.severity == ErrorSeverity.CRITICAL

    info = ErrorClassifier.classify(PermissionError("nope"), {})
    assert "permissions" in info.suggested_action.lower()


def test_error_recovery_manager_strategy_failure() -> None:
    manager = ErrorRecoveryManager()
    manager.register_recovery_strategy(
        ErrorCategory.INPUT_VALIDATION, lambda _info: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    info = ErrorClassifier.classify(ValueError("bad"), {})
    recovered, result = manager.handle_error(info)
    assert recovered is False
    assert result is None


def test_error_handler_and_safe_execute_recovery() -> None:
    def _boom() -> None:
        raise RuntimeError("bad")

    @error_handler(
        category=ErrorCategory.INPUT_VALIDATION, severity=ErrorSeverity.HIGH, fallback_result="x"
    )
    def _wrapped() -> str:
        raise ValueError("bad")

    assert _wrapped() == "x"

    def _recovery(_info):
        return "ok"

    from r2inspect.utils import error_handler as handler_mod

    old = handler_mod.global_error_manager.recovery_strategies.get(ErrorCategory.UNKNOWN)
    handler_mod.global_error_manager.register_recovery_strategy(ErrorCategory.UNKNOWN, _recovery)
    try:
        assert safe_execute(_boom, fallback_result="fallback") == "ok"
    finally:
        if old is not None:
            handler_mod.global_error_manager.register_recovery_strategy(ErrorCategory.UNKNOWN, old)
