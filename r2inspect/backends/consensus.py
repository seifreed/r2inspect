"""Run two backends and expose disagreements as first-class results."""

from __future__ import annotations

from typing import Any


def compare_results(left: dict[str, Any], right: dict[str, Any]) -> list[dict[str, Any]]:
    disagreements: list[dict[str, Any]] = []
    for field in ("file_info", "format_detection"):
        left_value = left.get(field, {})
        right_value = right.get(field, {})
        keys = set(left_value) | set(right_value)
        for key in sorted(keys):
            if left_value.get(key) != right_value.get(key):
                disagreements.append(
                    {
                        "field": f"{field}.{key}",
                        "left": left_value.get(key),
                        "right": right_value.get(key),
                        "status": "backend_disagreement",
                    }
                )
    return disagreements


class ConsensusInspector:
    def __init__(self, left: Any, right: Any, left_name: str, right_name: str) -> None:
        self.left = left
        self.right = right
        self.left_name = left_name
        self.right_name = right_name

    def analyze(self, **options: Any) -> dict[str, Any]:
        left_result = self.left.analyze(**options)
        right_result = self.right.analyze(**options)
        disagreements = compare_results(left_result, right_result)
        result = dict(left_result)
        result["backend"] = "consensus"
        result["backend_results"] = {
            self.left_name: left_result,
            self.right_name: right_result,
        }
        result["backend_disagreements"] = disagreements
        if disagreements:
            result["warnings"] = ["independent backends disagree"]
        return result

    def close(self) -> None:
        for backend in (self.left, self.right):
            close = getattr(backend, "close", None)
            if callable(close):
                close()

    def __enter__(self) -> ConsensusInspector:
        return self

    def __exit__(self, *_args: Any) -> bool:
        self.close()
        return False


__all__ = ["ConsensusInspector", "compare_results"]
