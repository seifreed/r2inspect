from __future__ import annotations

import pytest

from r2inspect.utils import error_handler


def test_error_classifier_and_stats() -> None:
    error_handler.reset_error_stats()
    info = error_handler.ErrorClassifier.classify(
        ValueError("bad"), {"analysis_type": "pe_analysis"}
    )
    assert info.category == error_handler.ErrorCategory.INPUT_VALIDATION
    assert info.severity == error_handler.ErrorSeverity.HIGH
    assert info.to_dict()["exception_message"] == "bad"

    recovered, result = error_handler.global_error_manager.handle_error(info)
    assert recovered in {False, True}
    stats = error_handler.get_error_stats()
    assert stats["total_errors"] >= 1


def test_error_handler_decorator_and_safe_execute() -> None:
    @error_handler.error_handler(
        category=error_handler.ErrorCategory.FILE_ACCESS,
        severity=error_handler.ErrorSeverity.HIGH,
        context={"analysis_type": "file_info"},
        fallback_result={"ok": False},
    )
    def _fail() -> dict[str, bool]:
        raise FileNotFoundError("missing")

    assert _fail() is None

    def _raise() -> None:
        raise RuntimeError("boom")

    assert error_handler.safe_execute(_raise, fallback_result="fallback") == "fallback"

    with pytest.raises(MemoryError):

        @error_handler.error_handler(
            category=error_handler.ErrorCategory.UNKNOWN,
            severity=error_handler.ErrorSeverity.CRITICAL,
            context={},
            fallback_result=None,
        )
        def _critical() -> None:
            raise MemoryError("oom")

        _critical()
