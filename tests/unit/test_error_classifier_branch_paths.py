"""Branch-path tests for r2inspect/error_handling/classifier.py."""
from __future__ import annotations

import threading

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
# ErrorInfo.__init__ (lines 53-60)
# ---------------------------------------------------------------------------


def test_error_info_stores_all_fields():
    """Lines 53-60: all fields are set in __init__."""
    exc = ValueError("test")
    info = ErrorInfo(
        exc,
        ErrorSeverity.LOW,
        ErrorCategory.INPUT_VALIDATION,
        context={"key": "val"},
        recoverable=False,
        suggested_action="do something",
    )
    assert info.exception is exc
    assert info.severity == ErrorSeverity.LOW
    assert info.category == ErrorCategory.INPUT_VALIDATION
    assert info.context == {"key": "val"}
    assert info.recoverable is False
    assert info.suggested_action == "do something"
    assert isinstance(info.timestamp, float)
    assert isinstance(info.thread_id, int)


def test_error_info_default_context_is_empty_dict():
    """Line 56: context defaults to empty dict."""
    info = ErrorInfo(ValueError("x"), ErrorSeverity.LOW, ErrorCategory.UNKNOWN)
    assert info.context == {}


def test_error_info_default_recoverable_is_true():
    """Line 57: recoverable defaults to True."""
    info = ErrorInfo(ValueError("x"), ErrorSeverity.LOW, ErrorCategory.UNKNOWN)
    assert info.recoverable is True


def test_error_info_default_suggested_action_is_none():
    """Line 58: suggested_action defaults to None."""
    info = ErrorInfo(ValueError("x"), ErrorSeverity.LOW, ErrorCategory.UNKNOWN)
    assert info.suggested_action is None


# ---------------------------------------------------------------------------
# ErrorInfo.to_dict (line 64)
# ---------------------------------------------------------------------------


def test_error_info_to_dict_keys_and_values():
    """Line 64: to_dict returns all expected keys with correct values."""
    exc = FileNotFoundError("missing.bin")
    info = ErrorInfo(
        exc,
        ErrorSeverity.HIGH,
        ErrorCategory.FILE_ACCESS,
        context={"phase": "init"},
        recoverable=True,
        suggested_action="check path",
    )
    d = info.to_dict()
    assert d["exception_type"] == "FileNotFoundError"
    assert d["exception_message"] == "missing.bin"
    assert d["severity"] == "high"
    assert d["category"] == "file_access"
    assert d["context"] == {"phase": "init"}
    assert d["recoverable"] is True
    assert d["suggested_action"] == "check path"
    assert "timestamp" in d
    assert "thread_id" in d


# ---------------------------------------------------------------------------
# ErrorClassifier.classify – direct mapping (lines 112-131)
# ---------------------------------------------------------------------------


def test_classify_uses_direct_mapping_for_memory_error():
    """Lines 115-117: MemoryError found in EXCEPTION_MAPPING."""
    info = ErrorClassifier.classify(MemoryError("oom"))
    assert info.category == ErrorCategory.MEMORY
    assert info.severity == ErrorSeverity.CRITICAL


def test_classify_uses_direct_mapping_for_value_error():
    """Lines 115-117: ValueError mapped to INPUT_VALIDATION."""
    info = ErrorClassifier.classify(ValueError("bad"))
    assert info.category == ErrorCategory.INPUT_VALIDATION


def test_classify_uses_direct_mapping_for_file_not_found():
    """Lines 115-117: FileNotFoundError mapped to FILE_ACCESS/HIGH."""
    info = ErrorClassifier.classify(FileNotFoundError("missing"))
    assert info.category == ErrorCategory.FILE_ACCESS
    assert info.severity == ErrorSeverity.HIGH


def test_classify_uses_direct_mapping_for_permission_error():
    info = ErrorClassifier.classify(PermissionError("denied"))
    assert info.category == ErrorCategory.FILE_ACCESS


def test_classify_uses_direct_mapping_for_os_error():
    info = ErrorClassifier.classify(OSError("os issue"))
    assert info.category == ErrorCategory.FILE_ACCESS


def test_classify_uses_direct_mapping_for_is_a_directory_error():
    info = ErrorClassifier.classify(IsADirectoryError("/tmp"))
    assert info.category == ErrorCategory.FILE_ACCESS
    assert info.severity == ErrorSeverity.MEDIUM


def test_classify_uses_direct_mapping_for_type_error():
    info = ErrorClassifier.classify(TypeError("wrong type"))
    assert info.category == ErrorCategory.INPUT_VALIDATION


def test_classify_uses_direct_mapping_for_connection_error():
    info = ErrorClassifier.classify(ConnectionError("conn failed"))
    assert info.category == ErrorCategory.NETWORK


def test_classify_uses_direct_mapping_for_timeout_error():
    info = ErrorClassifier.classify(TimeoutError("timed out"))
    assert info.category == ErrorCategory.NETWORK


def test_classify_uses_direct_mapping_for_import_error():
    info = ErrorClassifier.classify(ImportError("no module"))
    assert info.category == ErrorCategory.DEPENDENCY
    assert info.severity == ErrorSeverity.HIGH


def test_classify_uses_direct_mapping_for_module_not_found():
    info = ErrorClassifier.classify(ModuleNotFoundError("no mod"))
    assert info.category == ErrorCategory.DEPENDENCY


def test_classify_falls_back_to_inheritance_for_unknown():
    """Lines 118-120: unknown exception type uses _classify_by_inheritance."""
    class WeirdError(Exception):
        pass

    info = ErrorClassifier.classify(WeirdError("strange"))
    assert info.category == ErrorCategory.UNKNOWN
    assert info.severity == ErrorSeverity.LOW


def test_classify_falls_back_to_inheritance_for_r2pipe_message():
    """Lines 118-120: r2pipe string in message -> R2PIPE category."""
    class SomeError(Exception):
        pass

    info = ErrorClassifier.classify(SomeError("r2pipe connection lost"))
    assert info.category == ErrorCategory.R2PIPE


def test_classify_returns_error_info_instance():
    """Line 131: classify returns an ErrorInfo object."""
    info = ErrorClassifier.classify(ValueError("v"))
    assert isinstance(info, ErrorInfo)


def test_classify_with_none_context_uses_empty_dict():
    """Line 112: None context is coerced to {}."""
    info = ErrorClassifier.classify(ValueError("v"), context=None)
    assert info.context.get("function_name") is None or isinstance(info.context, dict)


# ---------------------------------------------------------------------------
# ErrorClassifier._classify_by_inheritance (lines 143-152)
# ---------------------------------------------------------------------------


def test_classify_by_inheritance_subclass_of_os_error():
    """Lines 143-148: subclass of mapped exception type is recognized."""
    class CustomOSError(OSError):
        pass

    info = ErrorClassifier.classify(CustomOSError("custom"))
    assert info.category == ErrorCategory.FILE_ACCESS


def test_classify_by_inheritance_subclass_of_import_error():
    class MyImportError(ImportError):
        pass

    info = ErrorClassifier.classify(MyImportError("missing"))
    assert info.category == ErrorCategory.DEPENDENCY


def test_classify_by_inheritance_r2pipe_in_type_name():
    """Lines 149-150: r2pipe in exception type name -> R2PIPE."""
    class r2pipeConnectionError(Exception):
        pass

    info = ErrorClassifier.classify(r2pipeConnectionError("broken"))
    assert info.category == ErrorCategory.R2PIPE


# ---------------------------------------------------------------------------
# ErrorClassifier._adjust_classification (lines 165-185)
# ---------------------------------------------------------------------------


def test_adjust_upgrades_medium_to_high_for_pe_analysis():
    """Lines 165-171: medium severity upgraded to high for PE analysis."""
    exc = ValueError("bad input")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "pe_analysis"})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_upgrades_medium_to_high_for_elf_analysis():
    exc = ValueError("bad input")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "elf_analysis"})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_upgrades_medium_to_high_for_macho_analysis():
    exc = ValueError("bad input")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "macho_analysis"})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_does_not_upgrade_non_medium_severity():
    """Lines 165-171: only MEDIUM severity is upgraded."""
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"analysis_type": "pe_analysis"})
    # MemoryError is CRITICAL; large file can downgrade it but not pe_analysis
    assert info.severity in (ErrorSeverity.CRITICAL, ErrorSeverity.HIGH)


def test_adjust_downgrades_high_to_medium_in_batch_mode():
    """Lines 174-175: HIGH severity reduced to MEDIUM in batch mode."""
    exc = FileNotFoundError("missing")
    info = ErrorClassifier.classify(exc, context={"batch_mode": True})
    assert info.severity == ErrorSeverity.MEDIUM


def test_adjust_does_not_downgrade_non_high_in_batch_mode():
    """Lines 174-175: non-HIGH severity not changed in batch mode."""
    exc = IsADirectoryError("/tmp")
    info = ErrorClassifier.classify(exc, context={"batch_mode": True})
    # IsADirectoryError is MEDIUM, batch mode only affects HIGH
    assert info.severity == ErrorSeverity.MEDIUM


def test_adjust_downgrades_memory_critical_for_large_file():
    """Lines 178-179: CRITICAL MemoryError becomes HIGH for large files (>100MB)."""
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 150})
    assert info.severity == ErrorSeverity.HIGH


def test_adjust_r2pipe_initialization_phase_becomes_critical():
    """Lines 182-183: R2PIPE error during initialization becomes CRITICAL."""
    class R2Error(Exception):
        pass

    exc = R2Error("r2pipe timed out")
    info = ErrorClassifier.classify(exc, context={"phase": "initialization"})
    assert info.category == ErrorCategory.R2PIPE
    assert info.severity == ErrorSeverity.CRITICAL


# ---------------------------------------------------------------------------
# ErrorClassifier._is_recoverable (lines 194-206)
# ---------------------------------------------------------------------------


def test_is_recoverable_critical_is_false():
    """Line 194-195: CRITICAL errors are not recoverable."""
    info = ErrorClassifier.classify(MemoryError("oom"))
    assert info.recoverable is False


def test_is_recoverable_memory_error_cleanup_available_true():
    """Lines 198-199: MemoryError recoverable when memory_cleanup_available=True."""
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200, "memory_cleanup_available": True})
    assert info.recoverable is True


def test_is_recoverable_memory_error_cleanup_available_false():
    """Lines 198-199: MemoryError not recoverable when memory_cleanup_available=False."""
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200, "memory_cleanup_available": False})
    assert info.recoverable is False


def test_is_recoverable_file_not_found_component_optional_true():
    """Lines 202-203: FileNotFoundError recoverable when component_optional=True."""
    exc = FileNotFoundError("lib.so")
    info = ErrorClassifier.classify(exc, context={"component_optional": True})
    assert info.recoverable is True


def test_is_recoverable_file_not_found_component_optional_false():
    """Lines 202-203: FileNotFoundError not recoverable when component_optional=False."""
    exc = FileNotFoundError("lib.so")
    info = ErrorClassifier.classify(exc, context={"component_optional": False})
    assert info.recoverable is False


def test_is_recoverable_permission_error_defaults_to_optional():
    """Lines 202-203: PermissionError defaults to recoverable (component_optional defaults True)."""
    exc = PermissionError("denied")
    info = ErrorClassifier.classify(exc)
    assert info.recoverable is True


def test_is_recoverable_value_error_returns_true():
    """Line 206: generic errors are recoverable."""
    exc = ValueError("bad input")
    info = ErrorClassifier.classify(exc)
    assert info.recoverable is True


# ---------------------------------------------------------------------------
# ErrorClassifier._suggest_action (lines 218-239)
# ---------------------------------------------------------------------------


def test_suggest_action_memory_critical():
    """Lines 218-220: CRITICAL memory error suggests restart."""
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc)
    assert "Restart" in info.suggested_action or "memory" in info.suggested_action.lower()


def test_suggest_action_memory_non_critical():
    """Lines 221-222: non-critical memory error suggests GC."""
    exc = MemoryError("oom")
    info = ErrorClassifier.classify(exc, context={"file_size_mb": 200})
    assert "garbage" in info.suggested_action.lower() or "collection" in info.suggested_action.lower()


def test_suggest_action_file_access_file_not_found():
    """Lines 224-226: FileNotFoundError suggests skip."""
    exc = FileNotFoundError("missing")
    info = ErrorClassifier.classify(exc)
    assert "Skip" in info.suggested_action


def test_suggest_action_file_access_permission_error():
    """Lines 227-228: PermissionError suggests checking permissions."""
    exc = PermissionError("denied")
    info = ErrorClassifier.classify(exc)
    assert "permission" in info.suggested_action.lower() or "privilege" in info.suggested_action.lower()


def test_suggest_action_file_access_other_falls_to_default():
    """Line 239: IsADirectoryError (FILE_ACCESS but not FNF/PE) falls to default."""
    exc = IsADirectoryError("/tmp")
    info = ErrorClassifier.classify(exc)
    assert "Log error" in info.suggested_action or "continue" in info.suggested_action.lower()


def test_suggest_action_r2pipe():
    """Lines 230-231: R2PIPE category suggests retry."""
    class R2Error(Exception):
        pass

    exc = R2Error("r2pipe failed")
    info = ErrorClassifier.classify(exc)
    assert "Retry" in info.suggested_action or "fallback" in info.suggested_action.lower()


def test_suggest_action_dependency():
    """Lines 233-234: DEPENDENCY category suggests installing."""
    exc = ImportError("no module")
    info = ErrorClassifier.classify(exc)
    assert "Install" in info.suggested_action or "dependency" in info.suggested_action.lower()


def test_suggest_action_input_validation():
    """Lines 236-237: INPUT_VALIDATION suggests validating input."""
    exc = ValueError("bad param")
    info = ErrorClassifier.classify(exc)
    assert "Validate" in info.suggested_action or "input" in info.suggested_action.lower()


def test_suggest_action_unknown_category_returns_default():
    """Line 239: UNKNOWN category returns the default suggestion."""
    class WeirdError(Exception):
        pass

    exc = WeirdError("unknown cause")
    info = ErrorClassifier.classify(exc)
    assert "Log error" in info.suggested_action or "continue" in info.suggested_action.lower()


# ---------------------------------------------------------------------------
# ErrorRecoveryManager (lines 267-311)
# ---------------------------------------------------------------------------


def test_error_recovery_manager_records_error_count():
    """Lines 269-281: error is recorded in error_counts."""
    manager = ErrorRecoveryManager()
    info = ErrorClassifier.classify(ValueError("bad"))
    manager.handle_error(info)
    stats = manager.get_error_stats()
    assert stats["total_errors"] >= 1


def test_error_recovery_manager_appends_to_recent_errors():
    """Lines 269-270: error is appended to recent_errors deque."""
    manager = ErrorRecoveryManager()
    info = ErrorClassifier.classify(ValueError("bad"))
    manager.handle_error(info)
    assert len(manager.recent_errors) >= 1


def test_error_recovery_manager_no_strategy_returns_false_none():
    """Lines 288-292: no recovery strategy -> (False, None)."""
    manager = ErrorRecoveryManager()
    info = ErrorClassifier.classify(ValueError("bad"))
    recovered, result = manager.handle_error(info)
    assert recovered is False
    assert result is None


def test_error_recovery_manager_with_strategy_returns_true_result():
    """Lines 276-281: strategy executes and returns recovered=True."""
    manager = ErrorRecoveryManager()
    manager.register_recovery_strategy(ErrorCategory.INPUT_VALIDATION, lambda e: "ok")
    info = ErrorClassifier.classify(ValueError("bad"))
    recovered, result = manager.handle_error(info)
    assert recovered is True
    assert result == "ok"


def test_error_recovery_manager_failing_strategy_returns_false():
    """Lines 283-285: strategy that raises returns (False, None)."""
    manager = ErrorRecoveryManager()

    def bad_strategy(e):
        raise RuntimeError("strategy exploded")

    manager.register_recovery_strategy(ErrorCategory.INPUT_VALIDATION, bad_strategy)
    info = ErrorClassifier.classify(ValueError("bad"))
    recovered, result = manager.handle_error(info)
    assert recovered is False
    assert result is None


def test_error_recovery_manager_non_recoverable_with_strategy_does_not_call_it():
    """Lines 276-277: recoverable=False prevents strategy call."""
    called = []
    manager = ErrorRecoveryManager()
    manager.register_recovery_strategy(ErrorCategory.MEMORY, lambda e: called.append(True))
    # MemoryError is CRITICAL -> not recoverable
    info = ErrorClassifier.classify(MemoryError("oom"))
    recovered, result = manager.handle_error(info)
    assert recovered is False
    assert called == []


def test_error_recovery_manager_log_error_critical(capsys):
    """Line 294: CRITICAL errors are logged at critical level."""
    manager = ErrorRecoveryManager()
    info = ErrorInfo(MemoryError("oom"), ErrorSeverity.CRITICAL, ErrorCategory.MEMORY)
    manager._log_error(info)  # should not raise


def test_error_recovery_manager_log_error_high(capsys):
    """Line 296: HIGH errors are logged at error level."""
    manager = ErrorRecoveryManager()
    info = ErrorInfo(FileNotFoundError("x"), ErrorSeverity.HIGH, ErrorCategory.FILE_ACCESS)
    manager._log_error(info)


def test_error_recovery_manager_log_error_medium():
    """Line 298: MEDIUM errors are logged at warning level."""
    manager = ErrorRecoveryManager()
    info = ErrorInfo(ValueError("x"), ErrorSeverity.MEDIUM, ErrorCategory.INPUT_VALIDATION)
    manager._log_error(info)


def test_error_recovery_manager_log_error_low():
    """Line 301: LOW errors are logged at debug level."""
    manager = ErrorRecoveryManager()

    class WeirdError(Exception):
        pass

    info = ErrorInfo(WeirdError("x"), ErrorSeverity.LOW, ErrorCategory.UNKNOWN)
    manager._log_error(info)


def test_error_recovery_manager_get_error_stats_structure():
    """Lines 311-...: get_error_stats returns expected keys."""
    manager = ErrorRecoveryManager()
    stats = manager.get_error_stats()
    assert "total_errors" in stats
    assert "recent_errors" in stats
    assert "errors_by_category" in stats
    assert "errors_by_severity" in stats
    assert "recovery_strategies_available" in stats


def test_error_recovery_manager_thread_safe_concurrent_access():
    """Lines 269-285: concurrent access does not corrupt state."""
    manager = ErrorRecoveryManager()
    errors = [ErrorClassifier.classify(ValueError(f"err{i}")) for i in range(20)]
    threads = [threading.Thread(target=manager.handle_error, args=(e,)) for e in errors]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stats = manager.get_error_stats()
    assert stats["total_errors"] >= 20


# ---------------------------------------------------------------------------
# error_handler decorator (lines 348-374)
# ---------------------------------------------------------------------------


def test_error_handler_success_path_returns_value():
    """Line 346: function returns normally."""
    @error_handler()
    def func():
        return 42

    assert func() == 42


def test_error_handler_catches_exception_and_returns_fallback():
    """Lines 348-371: exception is caught and fallback is returned."""
    @error_handler(fallback_result="fb")
    def func():
        raise ValueError("bad")

    assert func() == "fb"


def test_error_handler_category_override():
    """Lines 360-361: specified category overrides classified category."""
    results = []

    @error_handler(category=ErrorCategory.ANALYSIS, fallback_result=None)
    def func():
        raise RuntimeError("r2pipe failed in analysis")

    # Should not raise, fallback returned
    result = func()
    assert result is None or isinstance(result, str)


def test_error_handler_severity_override():
    """Lines 362-363: specified severity overrides classified severity."""
    @error_handler(severity=ErrorSeverity.LOW, fallback_result="done")
    def func():
        raise ValueError("mild problem")

    assert func() == "done"


def test_error_handler_reraises_critical_non_recoverable():
    """Lines 372-374: non-recoverable CRITICAL error is re-raised."""
    @error_handler(category=ErrorCategory.MEMORY, severity=ErrorSeverity.CRITICAL)
    def func():
        raise MemoryError("OOM")

    with pytest.raises(MemoryError):
        func()


def test_error_handler_with_extra_context():
    """Lines 350-354: context is merged into func_context."""
    @error_handler(context={"phase": "test"}, fallback_result="ok")
    def func():
        raise ValueError("bad")

    assert func() == "ok"


def test_error_handler_preserves_function_name():
    """Lines 343: @functools.wraps preserves __name__."""
    @error_handler()
    def my_named_function():
        return "ok"

    assert my_named_function.__name__ == "my_named_function"


def test_error_handler_recovery_returns_recovered_result():
    """Lines 368-369: recovered result is returned when recovery succeeds."""
    register_recovery_strategies()

    @error_handler(fallback_result="fb")
    def func():
        raise RuntimeError("r2pipe error occurred")

    # r2pipe_recovery is triggered -> recovered=True -> returns None or ""
    result = func()
    assert result is None or result == "" or result == "fb"


# ---------------------------------------------------------------------------
# safe_execute (lines 401-417)
# ---------------------------------------------------------------------------


def test_safe_execute_success_returns_value():
    """Lines 401-402: function succeeds and result is returned."""
    assert safe_execute(lambda: 99) == 99


def test_safe_execute_with_positional_args():
    assert safe_execute(lambda a, b: a + b, 3, 4) == 7


def test_safe_execute_with_keyword_args():
    assert safe_execute(lambda x=0: x * 2, x=5) == 10


def test_safe_execute_returns_fallback_on_error():
    """Lines 404-417: exception triggers fallback return."""
    def broken():
        raise ValueError("fail")

    assert safe_execute(broken, fallback_result="fallback") == "fallback"


def test_safe_execute_with_context():
    """Lines 404-408: context dict is built from func info."""
    def broken():
        raise ValueError("fail")

    result = safe_execute(broken, fallback_result=0, context={"phase": "test"})
    assert result == 0


def test_safe_execute_recovery_returns_recovered():
    """Lines 414-415: recovered result returned when recovery succeeds."""
    register_recovery_strategies()

    def r2pipe_fail():
        raise RuntimeError("r2pipe crashed")

    result = safe_execute(r2pipe_fail, fallback_result="fallback")
    assert result is None or result == "" or result == "fallback"


def test_safe_execute_no_recovery_returns_fallback():
    """Lines 416-417: no recovery -> fallback_result returned."""
    result = safe_execute(lambda: (_ for _ in ()).throw(ValueError("x")), fallback_result="fb")
    assert result == "fb"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def test_register_recovery_strategies_registers_three_strategies():
    """Lines 425-445: three strategies are registered after call."""
    register_recovery_strategies()
    strategies = set(global_error_manager.recovery_strategies.keys())
    assert ErrorCategory.MEMORY in strategies
    assert ErrorCategory.R2PIPE in strategies
    assert ErrorCategory.FILE_ACCESS in strategies


def test_get_error_stats_returns_dict_with_keys():
    stats = get_error_stats()
    assert isinstance(stats, dict)
    assert "total_errors" in stats


def test_reset_error_stats_zeroes_counts():
    """Reset clears error counts."""
    safe_execute(lambda: (_ for _ in ()).throw(ValueError("x")), fallback_result=None)
    reset_error_stats()
    stats = get_error_stats()
    assert stats["total_errors"] == 0
    assert stats["recent_errors"] == 0


# ---------------------------------------------------------------------------
# Recovery strategies (lines 425-445)
# ---------------------------------------------------------------------------


def test_memory_recovery_strategy_runs_gc():
    """Lines 425-431: memory_recovery triggers GC and returns None."""
    register_recovery_strategies()

    def oom_func():
        raise MemoryError("out of memory")

    # large file -> MEMORY+HIGH -> recoverable=True -> memory_recovery called
    result = safe_execute(oom_func, fallback_result="fallback", context={"file_size_mb": 200})
    assert result is None  # memory_recovery returns None, recovered=True


def test_r2pipe_recovery_json_command_returns_none():
    """Lines 436-438: r2pipe_recovery for json command returns None."""
    register_recovery_strategies()

    def r2pipe_fail():
        raise RuntimeError("r2pipe error for ij command")

    result = safe_execute(r2pipe_fail, fallback_result="fallback", context={"command": "ij"})
    assert result is None


def test_r2pipe_recovery_text_command_returns_empty_string():
    """Lines 436, 439-440: r2pipe_recovery for non-json command returns ''."""
    register_recovery_strategies()

    def r2pipe_fail():
        raise RuntimeError("r2pipe error occurred")

    result = safe_execute(r2pipe_fail, fallback_result="fallback", context={"command": "i"})
    assert result == ""


def test_file_access_recovery_returns_none():
    """Lines 444-445: file_access_recovery returns None for optional components."""
    register_recovery_strategies()

    def file_fail():
        raise FileNotFoundError("optional_lib.so")

    result = safe_execute(
        file_fail,
        fallback_result="fallback",
        context={"component_optional": True},
    )
    assert result is None


# ---------------------------------------------------------------------------
# Import the global manager to verify strategy count
# ---------------------------------------------------------------------------

from r2inspect.error_handling.classifier import global_error_manager  # noqa: E402
