#!/usr/bin/env python3
"""
Unified error handling strategy for r2inspect
"""

import functools
import threading
from collections import defaultdict, deque
from collections.abc import Callable
from enum import Enum
from typing import Any

from .logger import get_logger

logger = get_logger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels"""

    LOW = "low"  # Non-critical errors, analysis can continue
    MEDIUM = "medium"  # Moderate errors, some functionality may be affected
    HIGH = "high"  # Serious errors, significant functionality impact
    CRITICAL = "critical"  # Critical errors, analysis should be aborted


class ErrorCategory(Enum):
    """Error categories for classification"""

    INPUT_VALIDATION = "input_validation"
    FILE_ACCESS = "file_access"
    MEMORY = "memory"
    R2PIPE = "r2pipe"
    ANALYSIS = "analysis"
    NETWORK = "network"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class ErrorInfo:
    """Information about an error"""

    def __init__(
        self,
        exception: Exception,
        severity: ErrorSeverity,
        category: ErrorCategory,
        context: dict[str, Any] | None = None,
        recoverable: bool = True,
        suggested_action: str | None = None,
    ):
        self.exception = exception
        self.severity = severity
        self.category = category
        self.context = context or {}
        self.recoverable = recoverable
        self.suggested_action = suggested_action
        self.timestamp = __import__("time").time()
        self.thread_id = threading.get_ident()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/serialization"""
        return {
            "exception_type": type(self.exception).__name__,
            "exception_message": str(self.exception),
            "severity": self.severity.value,
            "category": self.category.value,
            "context": self.context,
            "recoverable": self.recoverable,
            "suggested_action": self.suggested_action,
            "timestamp": self.timestamp,
            "thread_id": self.thread_id,
        }


class ErrorClassifier:
    """Classify exceptions into categories and severities"""

    # Exception mapping to category and severity
    EXCEPTION_MAPPING = {
        # Memory errors
        MemoryError: (ErrorCategory.MEMORY, ErrorSeverity.CRITICAL),
        OSError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.MEDIUM),
        # File access errors
        FileNotFoundError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.HIGH),
        PermissionError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.HIGH),
        IsADirectoryError: (ErrorCategory.FILE_ACCESS, ErrorSeverity.MEDIUM),
        # Input validation
        ValueError: (ErrorCategory.INPUT_VALIDATION, ErrorSeverity.MEDIUM),
        TypeError: (ErrorCategory.INPUT_VALIDATION, ErrorSeverity.MEDIUM),
        # Network errors
        ConnectionError: (ErrorCategory.NETWORK, ErrorSeverity.MEDIUM),
        TimeoutError: (ErrorCategory.NETWORK, ErrorSeverity.MEDIUM),
        # Import/dependency errors
        ImportError: (ErrorCategory.DEPENDENCY, ErrorSeverity.HIGH),
        ModuleNotFoundError: (ErrorCategory.DEPENDENCY, ErrorSeverity.HIGH),
    }

    @classmethod
    def classify(cls, exception: Exception, context: dict[str, Any] | None = None) -> ErrorInfo:
        """
        Classify an exception

        Args:
            exception: The exception to classify
            context: Additional context information

        Returns:
            ErrorInfo object with classification
        """
        context = context or {}

        # Get base classification from mapping
        exc_type = type(exception)
        if exc_type in cls.EXCEPTION_MAPPING:
            category, severity = cls.EXCEPTION_MAPPING[exc_type]
        else:
            # Check parent classes
            category, severity = cls._classify_by_inheritance(exception)

        # Adjust based on context
        category, severity = cls._adjust_classification(exception, category, severity, context)

        # Determine recoverability
        recoverable = cls._is_recoverable(exception, severity, context)

        # Generate suggested action
        suggested_action = cls._suggest_action(exception, category, severity, context)

        return ErrorInfo(
            exception=exception,
            severity=severity,
            category=category,
            context=context,
            recoverable=recoverable,
            suggested_action=suggested_action,
        )

    @classmethod
    def _classify_by_inheritance(cls, exception: Exception) -> tuple:
        """Classify by checking exception inheritance"""
        for exc_type, (category, severity) in cls.EXCEPTION_MAPPING.items():
            if isinstance(exception, exc_type):
                return category, severity

        # Special checks for r2pipe related errors
        if "r2pipe" in str(type(exception)).lower() or "r2pipe" in str(exception).lower():
            return ErrorCategory.R2PIPE, ErrorSeverity.MEDIUM

        # Default classification
        return ErrorCategory.UNKNOWN, ErrorSeverity.LOW

    @classmethod
    def _adjust_classification(
        cls,
        exception: Exception,
        category: ErrorCategory,
        severity: ErrorSeverity,
        context: dict[str, Any],
    ) -> tuple:
        """Adjust classification based on context"""

        # Check if this is a critical analysis component
        if context.get("analysis_type") in [
            "pe_analysis",
            "elf_analysis",
            "macho_analysis",
        ]:
            if severity == ErrorSeverity.MEDIUM:
                severity = ErrorSeverity.HIGH

        # Check if this is batch processing
        if context.get("batch_mode") and severity == ErrorSeverity.HIGH:
            severity = ErrorSeverity.MEDIUM  # Be more tolerant in batch mode

        # Memory errors in large files
        if category == ErrorCategory.MEMORY and context.get("file_size_mb", 0) > 100:
            severity = ErrorSeverity.HIGH  # Expected for large files

        # R2pipe errors during initial analysis
        if category == ErrorCategory.R2PIPE and context.get("phase") == "initialization":
            severity = ErrorSeverity.CRITICAL

        return category, severity

    @classmethod
    def _is_recoverable(
        cls, exception: Exception, severity: ErrorSeverity, context: dict[str, Any]
    ) -> bool:
        """Determine if error is recoverable"""

        # Critical errors are generally not recoverable
        if severity == ErrorSeverity.CRITICAL:
            return False

        # Memory errors might be recoverable with cleanup
        if isinstance(exception, MemoryError):
            return bool(context.get("memory_cleanup_available", True))

        # File access errors for optional components are recoverable
        if isinstance(exception, FileNotFoundError | PermissionError):
            return bool(context.get("component_optional", True))

        # Most other errors are recoverable
        return True

    @classmethod
    def _suggest_action(
        cls,
        exception: Exception,
        category: ErrorCategory,
        severity: ErrorSeverity,
        context: dict[str, Any],
    ) -> str:
        """Suggest recovery action"""

        if category == ErrorCategory.MEMORY:
            if severity == ErrorSeverity.CRITICAL:
                return "Restart analysis with smaller file or increase memory limits"
            else:
                return "Trigger garbage collection and continue with reduced analysis"

        elif category == ErrorCategory.FILE_ACCESS:
            if isinstance(exception, FileNotFoundError):
                return "Skip this component and continue analysis"
            elif isinstance(exception, PermissionError):
                return "Check file permissions or run with appropriate privileges"

        elif category == ErrorCategory.R2PIPE:
            return "Retry command with fallback options or skip this analysis"

        elif category == ErrorCategory.DEPENDENCY:
            return "Install missing dependency or disable related functionality"

        elif category == ErrorCategory.INPUT_VALIDATION:
            return "Validate input and retry with corrected parameters"

        return "Log error and continue with remaining analysis"


class ErrorRecoveryManager:
    """Manage error recovery strategies"""

    def __init__(self):
        self.recovery_strategies = {}
        self.error_counts = defaultdict(int)
        self.recent_errors = deque(maxlen=100)
        self.lock = threading.Lock()

    def register_recovery_strategy(
        self, category: ErrorCategory, strategy: Callable[[ErrorInfo], Any]
    ):
        """Register a recovery strategy for an error category"""
        self.recovery_strategies[category] = strategy

    def handle_error(self, error_info: ErrorInfo) -> tuple[bool, Any]:
        """
        Handle an error with appropriate recovery strategy

        Args:
            error_info: Information about the error

        Returns:
            Tuple of (recovered, result)
        """
        with self.lock:
            # Record error
            self.error_counts[error_info.category] += 1
            self.recent_errors.append(error_info)

            # Log error appropriately
            self._log_error(error_info)

            # Check if we have a recovery strategy
            if error_info.category in self.recovery_strategies and error_info.recoverable:
                try:
                    strategy = self.recovery_strategies[error_info.category]
                    result = strategy(error_info)
                    logger.info(f"Successfully recovered from {error_info.category.value} error")
                    return True, result

                except Exception as recovery_error:
                    logger.error(f"Recovery strategy failed: {recovery_error}")
                    return False, None

            # No recovery possible
            return False, None

    def _log_error(self, error_info: ErrorInfo):
        """Log error with appropriate level"""
        error_dict = error_info.to_dict()

        if error_info.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"Critical error: {error_dict}")
        elif error_info.severity == ErrorSeverity.HIGH:
            logger.error(f"High severity error: {error_dict}")
        elif error_info.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"Medium severity error: {error_dict}")
        else:
            logger.debug(f"Low severity error: {error_dict}")

    def get_error_stats(self) -> dict[str, Any]:
        """Get error statistics"""
        with self.lock:
            recent_count = len(self.recent_errors)

            # Count by severity
            severity_counts: dict[str, int] = defaultdict(int)
            for error in self.recent_errors:
                severity_counts[error.severity.value] += 1

            return {
                "total_errors": sum(self.error_counts.values()),
                "recent_errors": recent_count,
                "errors_by_category": dict(self.error_counts),
                "errors_by_severity": dict(severity_counts),
                "recovery_strategies_available": len(self.recovery_strategies),
            }


# Global error recovery manager
global_error_manager = ErrorRecoveryManager()


def error_handler(
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    context: dict[str, Any] | None = None,
    fallback_result: Any = None,
):
    """
    Decorator for unified error handling

    Args:
        category: Error category override
        severity: Error severity override
        context: Additional context
        fallback_result: Result to return on unrecoverable error
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)

            except Exception as e:
                # Create context with function information
                func_context = {
                    "function_name": func.__name__,
                    "module": func.__module__,
                    **(context or {}),
                }

                # Classify error
                error_info = ErrorClassifier.classify(e, func_context)

                # Override classification if specified
                if category != ErrorCategory.UNKNOWN:
                    error_info.category = category
                if severity != ErrorSeverity.MEDIUM:
                    error_info.severity = severity

                # Attempt recovery
                recovered, result = global_error_manager.handle_error(error_info)

                if recovered:
                    return result
                elif error_info.recoverable:
                    return fallback_result
                else:
                    # Re-raise critical errors
                    raise

        return wrapper

    return decorator


def safe_execute(
    func: Callable,
    *args,
    fallback_result: Any = None,
    context: dict[str, Any] | None = None,
    **kwargs,
) -> Any:
    """
    Safely execute a function with error handling

    Args:
        func: Function to execute
        *args: Positional arguments
        fallback_result: Result to return on error
        context: Additional context
        **kwargs: Keyword arguments

    Returns:
        Function result or fallback_result on error
    """
    try:
        return func(*args, **kwargs)

    except Exception as e:
        func_context = {
            "function_name": getattr(func, "__name__", "unknown"),
            "module": getattr(func, "__module__", "unknown"),
            **(context or {}),
        }

        error_info = ErrorClassifier.classify(e, func_context)
        recovered, result = global_error_manager.handle_error(error_info)

        if recovered:
            return result
        else:
            return fallback_result


def register_recovery_strategies():
    """Register default recovery strategies"""

    def memory_recovery(error_info: ErrorInfo):
        """Recovery strategy for memory errors"""
        import gc

        # Force garbage collection
        for _ in range(3):
            gc.collect()
        logger.info("Performed aggressive garbage collection")
        return None

    def r2pipe_recovery(error_info: ErrorInfo):
        """Recovery strategy for r2pipe errors"""
        # Return safe defaults based on command type
        context = error_info.context
        if context.get("command", "").endswith("j"):
            return None  # JSON command default
        else:
            return ""  # Text command default

    def file_access_recovery(error_info: ErrorInfo):
        """Recovery strategy for file access errors"""
        logger.warning(f"File access error: {error_info.suggested_action}")
        return None  # Skip the operation

    # Register strategies
    global_error_manager.register_recovery_strategy(ErrorCategory.MEMORY, memory_recovery)
    global_error_manager.register_recovery_strategy(ErrorCategory.R2PIPE, r2pipe_recovery)
    global_error_manager.register_recovery_strategy(ErrorCategory.FILE_ACCESS, file_access_recovery)


# Initialize default recovery strategies
register_recovery_strategies()


def get_error_stats() -> dict[str, Any]:
    """Get global error statistics"""
    return global_error_manager.get_error_stats()


def reset_error_stats():
    """Reset error statistics"""
    global_error_manager.error_counts.clear()
    global_error_manager.recent_errors.clear()
