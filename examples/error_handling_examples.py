#!/usr/bin/env python3
"""
Error Handling Examples

This file demonstrates various usage patterns for the unified error handling system.

Copyright (C) 2025 Marc Rivero Lopez
Licensed under GPLv3
"""

from collections.abc import Callable

from r2inspect.error_handling import (
    FAIL_FAST_POLICY,
    RETRY_POLICY,
    SAFE_POLICY,
    ErrorHandlingStrategy,
    ErrorPolicy,
    handle_errors,
)
from r2inspect.error_handling.presets import (
    AGGRESSIVE_RETRY_POLICY,
    CIRCUIT_BREAK_POLICY,
    R2_ANALYSIS_POLICY,
    R2_JSON_DICT_POLICY,
    R2_JSON_LIST_POLICY,
    R2_TEXT_POLICY,
    create_custom_policy,
)

# ==============================================================================
# Example 1: Basic Fallback Pattern
# ==============================================================================


class BasicAnalyzer:
    """Simple analyzer with fallback error handling"""

    def __init__(self, r2):
        self.r2 = r2

    @handle_errors(SAFE_POLICY)
    def get_file_info(self) -> dict:
        """Returns file information or empty dict on error"""
        return self.r2.cmdj("ij")

    @handle_errors(R2_JSON_LIST_POLICY)
    def get_imports(self) -> list[dict]:
        """Returns imports or empty list on error"""
        return self.r2.cmdj("iij")

    @handle_errors(R2_TEXT_POLICY)
    def get_disassembly(self, address: str) -> str:
        """Returns disassembly or empty string on error"""
        return self.r2.cmd(f"pd 10 @ {address}")


# ==============================================================================
# Example 2: Retry Pattern for Unstable Operations
# ==============================================================================


class NetworkAnalyzer:
    """Analyzer with retry logic for network operations"""

    @handle_errors(RETRY_POLICY)
    def fetch_malware_signature(self, hash_value: str) -> dict:
        """Fetches signature from remote database with retry"""
        import requests

        response = requests.get(f"https://api.example.com/signatures/{hash_value}", timeout=10)
        return response.json()

    @handle_errors(AGGRESSIVE_RETRY_POLICY)
    def query_sandbox_api(self, file_hash: str) -> dict:
        """Queries sandbox API with aggressive retry"""
        import requests

        # This will retry up to 5 times with shorter delays
        response = requests.post(
            "https://sandbox.example.com/analyze",
            json={"hash": file_hash},
            timeout=10,
        )
        return response.json()


# ==============================================================================
# Example 3: Circuit Breaker for External Services
# ==============================================================================


class CloudAnalyzer:
    """Analyzer using circuit breaker for external service calls"""

    @handle_errors(CIRCUIT_BREAK_POLICY)
    def analyze_with_cloud_service(self, binary_path: str) -> dict:
        """
        Analyze binary using cloud service with circuit breaker.

        Circuit opens after 5 failures and returns empty dict for 60 seconds.
        """
        import requests

        with open(binary_path, "rb") as f:
            response = requests.post(
                "https://cloud-av.example.com/scan",
                files={"file": f},
                timeout=20,
            )
        return response.json()

    @handle_errors(R2_ANALYSIS_POLICY)
    def run_deep_analysis(self) -> dict:
        """
        Run radare2 analysis commands with circuit breaker.

        Uses R2_ANALYSIS_POLICY which is specifically tuned for
        unstable radare2 analysis commands.
        """
        return self.r2.cmdj("aaa")


# ==============================================================================
# Example 4: Custom Policy for Specific Requirements
# ==============================================================================


class CustomAnalyzer:
    """Analyzer with custom error handling policies"""

    def __init__(self, r2):
        self.r2 = r2

        # Create custom policy for memory-intensive operations
        self.memory_policy = ErrorPolicy(
            strategy=ErrorHandlingStrategy.FALLBACK,
            fallback_value=None,
            retryable_exceptions={ConnectionError, TimeoutError},
            fatal_exceptions={MemoryError, KeyboardInterrupt},
        )

        # Create custom policy for critical operations
        self.critical_policy = ErrorPolicy(
            strategy=ErrorHandlingStrategy.FAIL_FAST,
            fatal_exceptions={MemoryError, KeyboardInterrupt, SystemExit},
        )

    @handle_errors(RETRY_POLICY.copy_with_overrides(max_retries=10, retry_delay=0.2))
    def highly_unreliable_operation(self):
        """
        Operation that frequently fails but eventually succeeds.

        Uses modified RETRY_POLICY with more aggressive settings.
        """
        return self.r2.cmdj("unstable_command")

    def memory_intensive_analysis(self, _file_path: str) -> dict:
        """
        Memory-intensive operation with custom error handling.

        Returns None instead of raising on memory errors.
        """

        @handle_errors(self.memory_policy)
        def _analyze():
            # Simulate memory-intensive operation
            large_data = self.r2.cmdj("complex_analysis")
            return self._process_large_data(large_data)

        return _analyze()

    def validate_binary_format(self, _file_path: str):
        """
        Critical validation that should fail fast on errors.

        Any error here indicates a serious problem that needs
        immediate attention, so we fail fast.
        """

        @handle_errors(self.critical_policy)
        def _validate():
            file_info = self.r2.cmdj("ij")
            if not file_info.get("format"):
                raise ValueError("Invalid binary format")
            return file_info

        return _validate()

    def _process_large_data(self, data):
        """Helper method to process large datasets"""
        # Implementation details...
        return data


# ==============================================================================
# Example 5: Combining Multiple Strategies
# ==============================================================================


class HybridAnalyzer:
    """
    Analyzer demonstrating different strategies for different operations
    """

    def __init__(self, r2):
        self.r2 = r2

    @handle_errors(FAIL_FAST_POLICY)
    def initialize(self):
        """
        Initialization must succeed or fail fast.

        No fallback or retry - if init fails, something is seriously wrong.
        """
        self.file_info = self.r2.cmdj("ij")
        self.architecture = self.file_info["arch"]
        self.bits = self.file_info["bits"]

    @handle_errors(R2_JSON_DICT_POLICY)
    def get_optional_metadata(self) -> dict:
        """
        Optional metadata can use fallback.

        Analysis can continue even if this fails.
        """
        return self.r2.cmdj("iEj")

    @handle_errors(RETRY_POLICY)
    def get_critical_data(self) -> dict:
        """
        Critical data should retry on transient errors.

        This data is important enough to retry but not critical
        enough to fail the entire analysis.
        """
        return self.r2.cmdj("iij")

    @handle_errors(CIRCUIT_BREAK_POLICY)
    def query_external_intel(self, hash_value: str) -> dict:
        """
        External service calls should use circuit breaker.

        Protects against cascading failures when external service is down.
        """
        import requests

        response = requests.get(f"https://intel.example.com/lookup/{hash_value}", timeout=10)
        return response.json()


# ==============================================================================
# Example 6: Dynamic Policy Selection
# ==============================================================================


class AdaptiveAnalyzer:
    """
    Analyzer that selects error handling policy based on context
    """

    def __init__(self, r2, batch_mode=False):
        self.r2 = r2
        self.batch_mode = batch_mode

    def analyze_function(self, function_address: str) -> dict:
        """
        Analyze function with policy based on batch mode.

        In batch mode, use more tolerant error handling to avoid
        stopping the entire batch on one failure.
        """
        if self.batch_mode:
            policy = ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value={})
        else:
            policy = ErrorPolicy(strategy=ErrorHandlingStrategy.RETRY, max_retries=3)

        @handle_errors(policy)
        def _analyze():
            return self.r2.cmdj(f"afij @ {function_address}")

        return _analyze()


# ==============================================================================
# Example 7: Testing and Monitoring
# ==============================================================================


def monitor_error_handling():
    """
    Example of monitoring circuit breaker state
    """
    from r2inspect.error_handling.unified_handler import (
        get_circuit_breaker_stats,
        reset_circuit_breakers,
    )

    # Get current statistics
    stats = get_circuit_breaker_stats()

    for func_id, circuit_stats in stats.items():
        state = circuit_stats["state"]
        failures = circuit_stats["failure_count"]

        if state == "open":
            print(f"WARNING: Circuit breaker open for {func_id}")
            print(f"  Failures: {failures}")
            print(f"  Last failure: {circuit_stats['last_failure_time']}")

        elif failures > 0:
            print(f"INFO: {func_id} has {failures} recent failures")

    # Reset circuits if needed (e.g., after fixing an issue)
    # reset_circuit_breakers()


# ==============================================================================
# Example 8: Creating Reusable Policies
# ==============================================================================


class PolicyFactory:
    """
    Factory for creating commonly used policies
    """

    @staticmethod
    def for_file_operations() -> ErrorPolicy:
        """Policy for file I/O operations"""
        return ErrorPolicy(
            strategy=ErrorHandlingStrategy.RETRY,
            max_retries=2,
            retry_delay=0.1,
            retryable_exceptions={OSError, IOError, PermissionError},
            fatal_exceptions={MemoryError},
        )

    @staticmethod
    def for_network_operations() -> ErrorPolicy:
        """Policy for network operations"""
        return ErrorPolicy(
            strategy=ErrorHandlingStrategy.CIRCUIT_BREAK,
            circuit_threshold=5,
            circuit_timeout=30,
            max_retries=3,
            retry_delay=0.5,
            fallback_value=None,
            retryable_exceptions={ConnectionError, TimeoutError},
        )

    @staticmethod
    def for_optional_features() -> ErrorPolicy:
        """Policy for optional features"""
        return ErrorPolicy(strategy=ErrorHandlingStrategy.FALLBACK, fallback_value=None)

    @staticmethod
    def for_critical_operations() -> ErrorPolicy:
        """Policy for critical operations that must not fail"""
        return ErrorPolicy(
            strategy=ErrorHandlingStrategy.RETRY,
            max_retries=5,
            retry_delay=1.0,
            retry_backoff=2.0,
            fatal_exceptions={MemoryError, KeyboardInterrupt},
        )


# ==============================================================================
# Example 9: Decorator Stacking (Not Recommended)
# ==============================================================================


class LegacyAnalyzer:
    """
    Example showing why decorator stacking is NOT recommended
    """

    # BAD: Don't stack error handling decorators
    # @handle_errors(RETRY_POLICY)
    # @handle_errors(CIRCUIT_BREAK_POLICY)
    # def bad_example(self):
    #     pass

    # GOOD: Use a single policy with appropriate strategy
    @handle_errors(CIRCUIT_BREAK_POLICY)
    def good_example(self):
        """
        Circuit breaker already includes retry logic.
        No need to stack decorators.
        """
        return self.r2.cmdj("complex_command")


# ==============================================================================
# Example 10: Testing Error Handling
# ==============================================================================


def test_error_handling():
    """
    Example test cases for error handling
    """

    # Test 1: Fallback returns default value
    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=42))
    def failing_function():
        raise ValueError("Error")

    result = failing_function()
    if result != 42:
        raise AssertionError("Expected failing_function() to return 42")

    # Test 2: Retry succeeds after failures
    attempt_count = 0

    @handle_errors(RETRY_POLICY)
    def flaky_function():
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count < 3:
            raise ConnectionError("Not ready")
        return "success"

    result = flaky_function()
    if result != "success":
        raise AssertionError("Expected flaky_function() to return success")
    if attempt_count != 3:
        raise AssertionError("Expected attempt_count to be 3")

    # Test 3: Fail fast re-raises exception
    @handle_errors(FAIL_FAST_POLICY)
    def critical_function():
        raise ValueError("Critical error")

    try:
        critical_function()
        raise AssertionError("Should have raised")
    except ValueError:
        pass


if __name__ == "__main__":
    print("Error Handling Examples")
    print("=" * 60)
    print("\nThis file contains examples of using the unified error")
    print("handling system. See the code for detailed examples.")
    print("\nKey concepts:")
    print("  - Use SAFE_POLICY for optional data (fallback to {})")
    print("  - Use RETRY_POLICY for transient errors")
    print("  - Use CIRCUIT_BREAK_POLICY for external services")
    print("  - Use FAIL_FAST_POLICY for critical operations")
    print("  - Create custom policies for specific requirements")
    print("\nRun test_error_handling() to verify functionality.")
    print("=" * 60)

    # Run basic tests
    test_error_handling()
    print("\n✓ Basic tests passed")
