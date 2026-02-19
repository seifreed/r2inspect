from __future__ import annotations

from typing import Any

from r2inspect.modules.binbloom_analysis import run_binbloom_analysis


class _FakeAnalyzer:
    """Minimal fake analyzer to test run_binbloom_analysis paths."""

    default_capacity = 1000
    default_error_rate = 0.001
    filepath = "test.bin"

    def __init__(
        self,
        has_functions: bool = True,
        has_blooms: bool = True,
    ) -> None:
        self._has_functions = has_functions
        self._has_blooms = has_blooms

    def _init_result_structure(self, extra: dict[str, Any]) -> dict[str, Any]:
        base = {"available": False, "error": None}
        base.update(extra)
        return base

    def _mark_unavailable(
        self, result: dict[str, Any], msg: str, library_available: bool = False
    ) -> dict[str, Any]:
        result["available"] = False
        result["library_available"] = library_available
        result["error"] = msg
        return result

    def _extract_functions(self) -> list[dict[str, Any]]:
        if not self._has_functions:
            return []
        return [
            {"name": "main", "addr": 0x1000, "size": 100},
            {"name": "sub_2000", "addr": 0x2000, "size": 50},
        ]

    def _collect_function_blooms(
        self,
        functions: list,
        capacity: int,
        error_rate: float,
    ) -> tuple:
        if not self._has_blooms:
            return {}, {}, [], 0
        blooms = {"main": object(), "sub_2000": object()}
        signatures = {"main": "aabbcc", "sub_2000": "ddeeff"}
        all_instructions = ["mov", "push", "ret"]
        return blooms, signatures, all_instructions, len(functions)

    def _serialize_blooms(self, blooms: dict) -> dict:
        return {name: str(bloom) for name, bloom in blooms.items()}

    def _collect_unique_signatures(self, signatures: dict) -> set:
        return set(signatures.values())

    def _find_similar_functions(self, signatures: dict) -> list:
        return []

    def _add_binary_bloom(
        self,
        results: dict,
        all_instructions: list,
        capacity: int,
        error_rate: float,
    ) -> None:
        results["binary_signature"] = "binary_sig"

    def _calculate_bloom_stats(self, blooms: dict, capacity: int, error_rate: float) -> dict:
        return {"capacity": capacity, "error_rate": error_rate, "count": len(blooms)}


def test_bloom_unavailable_returns_error_result() -> None:
    analyzer = _FakeAnalyzer()
    result = run_binbloom_analysis(
        analyzer=analyzer,
        capacity=None,
        error_rate=None,
        bloom_available=False,
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert result["available"] is False
    assert "library" in result.get("error", "").lower()


def test_bloom_capacity_none_uses_default() -> None:
    analyzer = _FakeAnalyzer()
    result = run_binbloom_analysis(
        analyzer=analyzer,
        capacity=None,
        error_rate=0.001,
        bloom_available=True,
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert result["available"] is True
    assert result["capacity"] == analyzer.default_capacity


def test_bloom_error_rate_none_uses_default() -> None:
    analyzer = _FakeAnalyzer()
    result = run_binbloom_analysis(
        analyzer=analyzer,
        capacity=1000,
        error_rate=None,
        bloom_available=True,
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert result["available"] is True
    assert result["error_rate"] == analyzer.default_error_rate


def test_bloom_no_functions_returns_error() -> None:
    analyzer = _FakeAnalyzer(has_functions=False)
    result = run_binbloom_analysis(
        analyzer=analyzer,
        capacity=1000,
        error_rate=0.001,
        bloom_available=True,
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert result["error"] == "No functions found in binary"
    assert result["available"] is False


def test_bloom_no_function_blooms_returns_error() -> None:
    analyzer = _FakeAnalyzer(has_functions=True, has_blooms=False)
    result = run_binbloom_analysis(
        analyzer=analyzer,
        capacity=1000,
        error_rate=0.001,
        bloom_available=True,
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert "No functions could be analyzed" in result["error"]


def test_bloom_successful_analysis() -> None:
    analyzer = _FakeAnalyzer(has_functions=True, has_blooms=True)
    result = run_binbloom_analysis(
        analyzer=analyzer,
        capacity=1000,
        error_rate=0.001,
        bloom_available=True,
        log_debug=lambda _: None,
        log_error=lambda _: None,
    )
    assert result["available"] is True
    assert result["total_functions"] == 2
    assert result["analyzed_functions"] == 2
    assert len(result["function_blooms"]) == 2
    assert result["unique_signatures"] > 0
    assert "bloom_stats" in result


def test_bloom_debug_messages_called() -> None:
    messages = []
    analyzer = _FakeAnalyzer()
    run_binbloom_analysis(
        analyzer=analyzer,
        capacity=1000,
        error_rate=0.001,
        bloom_available=True,
        log_debug=messages.append,
        log_error=lambda _: None,
    )
    assert len(messages) >= 2
    assert any("Starting" in m for m in messages)
    assert any("completed" in m for m in messages)
