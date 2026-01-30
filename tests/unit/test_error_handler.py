import pytest

from r2inspect.utils.error_handler import (
    ErrorCategory,
    ErrorClassifier,
    ErrorSeverity,
    error_handler,
    get_error_stats,
    reset_error_stats,
    safe_execute,
)


def test_error_classifier_memory_error():
    err = MemoryError("oom")
    info = ErrorClassifier.classify(err, {"file_size_mb": 200})
    assert info.category == ErrorCategory.MEMORY
    assert info.severity in {ErrorSeverity.HIGH, ErrorSeverity.CRITICAL}
    if info.severity == ErrorSeverity.CRITICAL:
        assert info.recoverable is False
    else:
        assert info.recoverable is True


def test_error_handler_decorator_returns_fallback_on_recoverable():
    reset_error_stats()

    @error_handler(category=ErrorCategory.INPUT_VALIDATION, fallback_result="fallback")
    def boom():
        raise ValueError("bad")

    assert boom() == "fallback"
    stats = get_error_stats()
    assert stats["total_errors"] >= 1


def test_error_handler_re_raises_on_critical():
    @error_handler(category=ErrorCategory.MEMORY, severity=ErrorSeverity.CRITICAL)
    def boom():
        raise MemoryError("oom")

    with pytest.raises(MemoryError):
        boom()


def test_safe_execute_returns_fallback():
    def boom():
        raise FileNotFoundError("missing")

    assert safe_execute(boom, fallback_result=None) is None
