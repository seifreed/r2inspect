"""Normalize analyzer error states without turning failures into clean results."""

from __future__ import annotations

from typing import Any


def normalize_analyzer_results(results: dict[str, Any]) -> dict[str, Any]:
    """Attach explicit status and clear boolean detections on failed analyzers."""
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("error"):
                text = str(value["error"]).lower()
                if "timeout" in text:
                    status = "timed_out"
                elif "unsupported" in text:
                    status = "unsupported"
                elif "dependency" in text or value.get("library_available") is False:
                    status = "dependency_unavailable"
                else:
                    status = "failed"
                value["status"] = status
                if "detected" in value:
                    value["detected"] = None
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(results)
    return results


__all__ = ["normalize_analyzer_results"]
