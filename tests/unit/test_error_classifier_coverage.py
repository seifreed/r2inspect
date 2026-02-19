#!/usr/bin/env python3
"""Coverage tests for r2inspect/error_handling/classifier.py"""
from __future__ import annotations

import threading
import time

import pytest

from r2inspect.error_handling.classifier import (
    ErrorCategory,
    ErrorClassifier,
    ErrorInfo,
    ErrorRecoveryManager,
    ErrorSeverity,
    error_handler,
    get_error_stats,
    register_recovery_strategies,
    reset_error_stats,
    safe_execute,
)


# ---------------------------------------------------------------------------
# ErrorSeverity / ErrorCategory enum coverage
# ---------------------------------------------------------------------------

def test_error_severity_values_are_distinct():
    values = {s.value for s in ErrorSeverity}
    assert len(values) == len(ErrorSeverity)


def test_error_category_values_are_distinct():
    values = {c.value for c in ErrorCategory}
    assert len(values) == len(ErrorCategory)


# ---------------------------------------------------------------------------
# ErrorInfo
# ---------------------------------------------------------------------------

def test_error_info_default_context():
    exc = ValueError("bad input")
    info = ErrorInfo(exc, ErrorSeverity.LOW, ErrorCategory.INPUT_VALIDATION)
    assert info.context == {}
    assert info.recoverable is True
    assert info.suggested_action is None
    assert isinstance(info.timestamp, float)
    assert isinstance(info.thread_id, int)


def test_error_info_to_dict_contains_required_keys():
    exc = MemoryError("oom")
    info = ErrorInfo(
        exc,
        ErrorSeverity.CRITICAL,
        ErrorCategory.MEMORY,
        context={"key": "val"},
        recoverable=False,
        suggested_action="free memory",
    )
    d = info.to_dict()
    assert d["exception_type"] == "MemoryError"
    assert d["exception_message"] == "oom"
    assert d["severity"] == "critical"
    assert d["category"] == "memory"
    assert d["context"] == {"key": "val"}
    assert d["recoverable"] is False
    assert d["suggested_action"] == "free memory"
    assert "timestamp" in d
    assert "thread_id" in d


# ---------------------------------------------------------------------------
# ErrorClassifier.classify – direct mapping
# ---------------------------------------------------------------------------

def test_classify_memory_error():
    info = ErrorClassifier.classify(MemoryError("oom"))
    assert info.category == ErrorCategory.MEMORY
    assert info.severity == ErrorSeverity.CRITICAL


def test_classify_file_not_found_error():
    info = ErrorClassifier.classify(FileNotFoundError("missing"))
    assert info.category == ErrorCategory.FILE_ACCESS
    assert info.severity == ErrorSeverity.HIGH


def test_classify_permission_error():
    info = ErrorClassifier.classify(PermissionError("denied"))
    assert info.category == ErrorCategory.FILE_ACCESS


def test_classify_is_a_directory_error():
    info = ErrorClassifier.classify(IsADirectoryError("/tmp"))
    assert info.category == ErrorCategory.FILE_ACCESS
    assert info.severity == ErrorSeverity.MEDIUM


def test_classify_os_error():
    info = ErrorClassifier.classify(OSError("os failure"))
    assert info.category == ErrorCategory.FILE_ACCESS


def test_classify_value_error():
    info = ErrorClassifier.classify(ValueError("bad value"))
    assert info.category == ErrorCategory.INPUT_VALIDATION
    assert info.severity == ErrorSeverity.MEDIUM


def test_classify_type_error():
    info = ErrorClassifier.classify(TypeError("bad type"))
    assert info.category == ErrorCategory.INPUT_VALIDATION


def test_classify_connection_error():
    info = ErrorClassifier.classify(ConnectionError("conn"))
    assert info.category == ErrorCategory.NETWORK


def test_classify_timeout_error():
    info = ErrorClassifier.classify(TimeoutError("timed out"))
    assert info.category == ErrorCategory.NETWORK


def test_classify_import_error():
    info = ErrorClassifier.classify(ImportError("no module"))
    assert info.category == ErrorCategory.DEPENDENCY
    assert info.severity == ErrorSeverity.HIGH


def test_classify_module_not_found_error():
    info = ErrorClassifier.classify(ModuleNotFoundError("no mod"))
    assert info.category == ErrorCategory.DEPENDENCY


# ---------------------------------------------------------------------------
# ErrorClassifier._classify_by_inheritance
# ---------------------------------------------------------------------------

def test_classify_by_inheritance_unknown_exception():
    class MyWeirdError(Exception):
        pass

    info = ErrorClassifier.classify(MyWeirdError("weird"))
    assert info.category == ErrorCategory.UNKNOWN
    assert info.severity == ErrorSeverity.LOW


def test_classify_by_inheritance_r2pipe_in_message():
    class SomeError(Exception):
        pass

    exc = SomeError("r2pipe connection failed")
    info = ErrorClassifier.classify(exc)
    assert info.category == ErrorCategory.R2PIPE
    assert info.severity == ErrorSeverity.MEDIUM


def test_classify_by_inheritance_subclass_of_mapped_type():
    class CustomOSError(OSError):
        pass

    info = ErrorClassifier.classify(CustomOSError("custom os"))
    assert info.category == ErrorCategory.FILE_ACCESS


# ---------------------------------------------------------------------------
# ErrorClassifier._adjust_classification
# ---------------------------------------------------------------------------

def test_adjust_classification_analysis_type_upgrades_medium_to_high():
    exc = ValueError("bad")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "pe_analysis"})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_classification_elf_analysis_type():
    exc = ValueError("bad")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "elf_analysis"})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_classification_macho_analysis_type():
    exc = ValueError("bad")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "macho_analysis"})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_classification_batch_mode_downgrades_high_to_medium():
    exc = FileNotFoundError("missing")
    info = ErrorClassifier.classify(exc, context={"batch_mode": True})
    assert info.severity == ErrorSeverity.MEDIUM


def test_adjust_classification_memory_large_file():
    exc = MemoryError("oom")
    # Large file causes memory CRITICAL to be re-evaluated; memory + large file -> HIGH
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200})
    assert info.category == ErrorCategory.MEMORY
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_classification_r2pipe_initialization_phase():
    class R2Error(Exception):
        pass

    exc = R2Error("r2pipe failed")
    info = ErrorClassifier.classify(exc, context={"phase": "initialization"})
    assert info.category == ErrorCategory.R2PIPE
    assert info.severity == ErrorSeverity.CRITICAL


# ---------------------------------------------------------------------------
# ErrorClassifier._is_recoverable
# ---------------------------------------------------------------------------

def test_is_recoverable_critical_is_false():
    exc = MemoryError("oom")
    # large file downgrades CRITICAL to HIGH, but direct: use context that keeps CRITICAL
    info = ErrorClassifier.classify(exc)
    # CRITICAL -> not recoverable
    assert info.recoverable is False


def test_is_recoverable_memory_with_cleanup_available():
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200, "memory_cleanup_available": True})
    # large file -> HIGH severity -> check memory recovery
    assert info.recoverable is True


def test_is_recoverable_memory_cleanup_not_available():
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200, "memory_cleanup_available": False})
    assert info.recoverable is False


def test_is_recoverable_file_not_found_component_optional_true():
    exc = FileNotFoundError("missing")
    info = ErrorClassifier.classify(exc, context={"component_optional": True})
    assert info.recoverable is True


def test_is_recoverable_file_not_found_component_optional_false():
    exc = FileNotFoundError("missing")
    info = ErrorClassifier.classify(exc, context={"component_optional": False})
    assert info.recoverable is False


def test_is_recoverable_permission_error_default_optional():
    exc = PermissionError("denied")
    info = ErrorClassifier.classify(exc)
    # component_optional defaults to True
    assert info.recoverable is True


def test_is_recoverable_generic_error_is_true():
    exc = ValueError("bad")
    info = ErrorClassifier.classify(exc)
    assert info.recoverable is True


# ---------------------------------------------------------------------------
# ErrorClassifier._suggest_action
# ---------------------------------------------------------------------------

def test_suggest_action_memory_critical():
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc)
    assert "Restart" in info.suggested_action or "memory" in info.suggested_action.lower()


def test_suggest_action_memory_non_critical():
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200})
    assert "garbage" in info.suggested_action.lower() or "collection" in info.suggested_action.lower()


def test_suggest_action_file_not_found():
    exc = FileNotFoundError("missing")
    info = ErrorClassifier.classify(exc)
    assert "Skip" in info.suggested_action


def test_suggest_action_permission_error():
    exc = PermissionError("denied")
    info = ErrorClassifier.classify(exc)
    assert "permission" in info.suggested_action.lower() or "privilege" in info.suggested_action.lower()


def test_suggest_action_r2pipe():
    class R2Error(Exception):
        pass

    exc = R2Error("r2pipe error")
    info = ErrorClassifier.classify(exc)
    assert "Retry" in info.suggested_action or "fallback" in info.suggested_action.lower()


def test_suggest_action_dependency():
    exc = ImportError("missing dep")
    info = ErrorClassifier.classify(exc)
    assert "dependency" in info.suggested_action.lower() or "Install" in info.suggested_action


def test_suggest_action_input_validation():
    exc = ValueError("bad input")
    info = ErrorClassifier.classify(exc)
    assert "Validate" in info.suggested_action or "input" in info.suggested_action.lower()


def test_suggest_action_unknown_category():
    class MyError(Exception):
        pass

    exc = MyError("unknown")
    info = ErrorClassifier.classify(exc)
    assert "Log error" in info.suggested_action or "continue" in info.suggested_action.lower()


# ---------------------------------------------------------------------------
# ErrorRecoveryManager
# ---------------------------------------------------------------------------

def test_error_recovery_manager_handle_error_no_strategy():
    manager = ErrorRecoveryManager()
    exc = ValueError("no strategy")
    error_info = ErrorClassifier.classify(exc)
    recovered, result = manager.handle_error(error_info)
    assert recovered is False
    assert result is None


def test_error_recovery_manager_with_strategy_succeeds():
    manager = ErrorRecoveryManager()
    manager.register_recovery_strategy(ErrorCategory.INPUT_VALIDATION, lambda e: "recovered")
    exc = ValueError("bad")
    error_info = ErrorClassifier.classify(exc)
    recovered, result = manager.handle_error(error_info)
    assert recovered is True
    assert result == "recovered"


def test_error_recovery_manager_strategy_raises_returns_false():
    manager = ErrorRecoveryManager()

    def failing_strategy(e):
        raise RuntimeError("strategy failed")

    manager.register_recovery_strategy(ErrorCategory.INPUT_VALIDATION, failing_strategy)
    exc = ValueError("bad")
    error_info = ErrorClassifier.classify(exc)
    recovered, result = manager.handle_error(error_info)
    assert recovered is False
    assert result is None


def test_error_recovery_manager_non_recoverable_no_strategy():
    manager = ErrorRecoveryManager()
    exc = MemoryError("oom")
    error_info = ErrorClassifier.classify(exc)
    # CRITICAL -> not recoverable
    recovered, result = manager.handle_error(error_info)
    assert recovered is False


def test_error_recovery_manager_log_error_all_severities():
    manager = ErrorRecoveryManager()
    for severity in ErrorSeverity:
        exc = ValueError("test")
        error_info = ErrorInfo(exc, severity, ErrorCategory.UNKNOWN)
        # Should not raise
        manager._log_error(error_info)


def test_error_recovery_manager_get_error_stats():
    manager = ErrorRecoveryManager()
    exc = ValueError("bad")
    error_info = ErrorClassifier.classify(exc)
    manager.handle_error(error_info)
    stats = manager.get_error_stats()
    assert stats["total_errors"] >= 1
    assert "errors_by_category" in stats
    assert "errors_by_severity" in stats
    assert "recovery_strategies_available" in stats


def test_error_recovery_manager_thread_safety():
    manager = ErrorRecoveryManager()
    errors = []
    for _ in range(10):
        errors.append(ErrorClassifier.classify(ValueError("concurrent")))

    threads = [threading.Thread(target=manager.handle_error, args=(e,)) for e in errors]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = manager.get_error_stats()
    assert stats["total_errors"] >= 10


# ---------------------------------------------------------------------------
# error_handler decorator
# ---------------------------------------------------------------------------

def test_error_handler_decorator_success_path():
    @error_handler(category=ErrorCategory.ANALYSIS, severity=ErrorSeverity.LOW)
    def my_func():
        return 42

    assert my_func() == 42


def test_error_handler_decorator_returns_fallback_on_recoverable_error():
    @error_handler(
        category=ErrorCategory.INPUT_VALIDATION,
        severity=ErrorSeverity.MEDIUM,
        fallback_result="fallback",
    )
    def my_func():
        raise ValueError("bad")

    result = my_func()
    assert result == "fallback"


def test_error_handler_decorator_reraises_critical_unrecoverable():
    @error_handler(
        category=ErrorCategory.MEMORY,
        severity=ErrorSeverity.CRITICAL,
        fallback_result=None,
    )
    def my_func():
        raise MemoryError("oom")

    with pytest.raises(MemoryError):
        my_func()


def test_error_handler_decorator_with_context():
    @error_handler(
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.LOW,
        context={"custom_key": "custom_val"},
        fallback_result="done",
    )
    def my_func():
        raise RuntimeError("fail")

    result = my_func()
    assert result == "done"


def test_error_handler_preserves_function_name():
    @error_handler()
    def my_named_function():
        return "ok"

    assert my_named_function.__name__ == "my_named_function"


# ---------------------------------------------------------------------------
# safe_execute
# ---------------------------------------------------------------------------

def test_safe_execute_success():
    result = safe_execute(lambda: 99)
    assert result == 99


def test_safe_execute_with_args():
    result = safe_execute(lambda a, b: a + b, 3, 4)
    assert result == 7


def test_safe_execute_returns_fallback_on_error():
    def broken():
        raise ValueError("fail")

    result = safe_execute(broken, fallback_result="fallback")
    assert result == "fallback"


def test_safe_execute_with_context():
    def broken():
        raise ValueError("fail")

    result = safe_execute(broken, fallback_result=0, context={"phase": "test"})
    assert result == 0


def test_safe_execute_with_kwargs():
    result = safe_execute(lambda x=0: x * 2, x=5)
    assert result == 10


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def test_register_recovery_strategies_does_not_raise():
    register_recovery_strategies()


def test_get_error_stats_returns_dict():
    stats = get_error_stats()
    assert isinstance(stats, dict)
    assert "total_errors" in stats


def test_reset_error_stats_clears_counts():
    # Generate some errors first
    safe_execute(lambda: (_ for _ in ()).throw(ValueError("x")), fallback_result=None)
    reset_error_stats()
    stats = get_error_stats()
    assert stats["total_errors"] == 0
    assert stats["recent_errors"] == 0


# ---------------------------------------------------------------------------
# Recovery strategy inner functions (lines 425-445)
# ---------------------------------------------------------------------------

def test_memory_recovery_strategy_is_triggered():
    """Trigger memory_recovery (lines 425-431) via safe_execute with large file context."""
    register_recovery_strategies()

    def oom():
        raise MemoryError("out of memory")

    # large file -> MEMORY+HIGH, recoverable=True -> memory_recovery is called
    result = safe_execute(oom, fallback_result="fallback", context={"file_size_mb": 200})
    # memory_recovery returns None -> recovered=True -> returns None
    assert result is None


def test_r2pipe_recovery_strategy_json_command():
    """Trigger r2pipe_recovery (lines 436-438) for a command ending in 'j'."""
    register_recovery_strategies()

    def r2pipe_fail():
        raise RuntimeError("r2pipe connection timeout")

    result = safe_execute(
        r2pipe_fail, fallback_result="fallback", context={"command": "ij"}
    )
    # r2pipe_recovery: command ends with 'j' -> returns None -> recovered=True
    assert result is None


def test_r2pipe_recovery_strategy_text_command():
    """Trigger r2pipe_recovery (lines 436, 439-440) for a text command."""
    register_recovery_strategies()

    def r2pipe_fail():
        raise RuntimeError("r2pipe error occurred")

    result = safe_execute(
        r2pipe_fail, fallback_result="fallback", context={"command": "i"}
    )
    # r2pipe_recovery: command does not end with 'j' -> returns "" -> recovered=True
    assert result == ""


def test_file_access_recovery_strategy():
    """Trigger file_access_recovery (lines 444-445) via safe_execute."""
    register_recovery_strategies()

    def file_fail():
        raise FileNotFoundError("component.dll not found")

    result = safe_execute(
        file_fail,
        fallback_result="fallback",
        context={"component_optional": True},
    )
    # file_access_recovery returns None -> recovered=True -> returns None
    assert result is None


def test_error_handler_returns_recovered_result():
    """Cover line 369: return result after successful recovery."""
    register_recovery_strategies()

    @error_handler(fallback_result="fb")
    def r2pipe_failing_func():
        raise RuntimeError("r2pipe crashed")

    # r2pipe_recovery will be triggered (R2PIPE category, MEDIUM severity, recoverable)
    result = r2pipe_failing_func()
    # recovery returns None or "" - both indicate recovery happened (line 369 hit)
    assert result is None or result == ""


def test_safe_execute_returns_recovered_result():
    """Cover line 415: return result after successful recovery in safe_execute."""
    register_recovery_strategies()

    def r2pipe_fail():
        raise RuntimeError("r2pipe failure")

    result = safe_execute(r2pipe_fail, fallback_result="fallback")
    # r2pipe_recovery is triggered -> recovered=True -> line 415 hit
    assert result is None or result == ""
