"""Branch-path coverage for r2inspect/modules/resource_analysis.py."""

from __future__ import annotations

from r2inspect.modules.resource_analysis import run_resource_analysis


# ---------------------------------------------------------------------------
# Minimal analyzer stubs (no mocks – real plain Python objects)
# ---------------------------------------------------------------------------


class _BASE_RESULT:
    """Shared base result template."""

    @staticmethod
    def make() -> dict:
        return {
            "has_resources": False,
            "resource_directory": None,
            "total_resources": 0,
            "total_size": 0,
            "resource_types": [],
            "resources": [],
            "version_info": None,
            "manifest": None,
            "icons": [],
            "strings": [],
            "suspicious_resources": [],
            "statistics": {},
        }


class AnalyzerNoResources:
    """Simulates a binary with no resource directory."""

    def _init_result_structure(self, extra: dict) -> dict:
        result = _BASE_RESULT.make()
        result.update(extra)
        return result

    def _get_resource_directory(self) -> None:
        return None


class AnalyzerWithResources:
    """Simulates a binary that has resources and all helper methods succeed."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _init_result_structure(self, extra: dict) -> dict:
        result = _BASE_RESULT.make()
        result.update(extra)
        return result

    def _get_resource_directory(self) -> dict:
        return {"offset": 0x1000, "size": 256}

    def _parse_resources(self) -> list:
        return [
            {"type": "RT_ICON", "size": 48},
            {"type": "RT_VERSION", "size": 120},
            {"type": "RT_MANIFEST", "size": 512},
        ]

    def _analyze_resource_types(self, result: dict, resources: list) -> None:
        self.calls.append("analyze_resource_types")
        result["resource_types"] = ["RT_ICON", "RT_VERSION", "RT_MANIFEST"]

    def _extract_version_info(self, result: dict, resources: list) -> None:
        self.calls.append("extract_version_info")
        result["version_info"] = {"version": "1.0.0"}

    def _extract_manifest(self, result: dict, resources: list) -> None:
        self.calls.append("extract_manifest")
        result["manifest"] = "<assembly/>"

    def _extract_icons(self, result: dict, resources: list) -> None:
        self.calls.append("extract_icons")
        result["icons"] = [{"size": 48}]

    def _extract_strings(self, result: dict, resources: list) -> None:
        self.calls.append("extract_strings")
        result["strings"] = ["hello"]

    def _calculate_statistics(self, result: dict, resources: list) -> None:
        self.calls.append("calculate_statistics")
        result["statistics"] = {"total_size": 680}

    def _check_suspicious_resources(self, result: dict, resources: list) -> None:
        self.calls.append("check_suspicious_resources")


class AnalyzerWithEmptyResources:
    """Resource directory present but _parse_resources returns empty list."""

    def _init_result_structure(self, extra: dict) -> dict:
        result = _BASE_RESULT.make()
        result.update(extra)
        return result

    def _get_resource_directory(self) -> dict:
        return {"offset": 0x2000}

    def _parse_resources(self) -> list:
        return []


class AnalyzerRaisingOnParse:
    """Raises an exception during _parse_resources to exercise error handler."""

    def _init_result_structure(self, extra: dict) -> dict:
        result = _BASE_RESULT.make()
        result.update(extra)
        return result

    def _get_resource_directory(self) -> dict:
        return {"offset": 0x3000}

    def _parse_resources(self) -> list:
        raise RuntimeError("parse failed")


class SilentLogger:
    def error(self, *args, **kwargs) -> None:
        pass

    def debug(self, *args, **kwargs) -> None:
        pass

    def warning(self, *args, **kwargs) -> None:
        pass


# ---------------------------------------------------------------------------
# Tests – no resources path (lines 32-33)
# ---------------------------------------------------------------------------


def test_run_resource_analysis_returns_available_when_no_resource_dir():
    result = run_resource_analysis(AnalyzerNoResources(), SilentLogger())
    assert result["available"] is True
    assert result["has_resources"] is False
    assert result["resource_directory"] is None


# ---------------------------------------------------------------------------
# Tests – resources present path (lines 35-57)
# ---------------------------------------------------------------------------


def test_run_resource_analysis_sets_has_resources_true():
    analyzer = AnalyzerWithResources()
    result = run_resource_analysis(analyzer, SilentLogger())
    assert result["has_resources"] is True


def test_run_resource_analysis_sets_resource_directory():
    analyzer = AnalyzerWithResources()
    result = run_resource_analysis(analyzer, SilentLogger())
    assert result["resource_directory"] == {"offset": 0x1000, "size": 256}


def test_run_resource_analysis_counts_resources_correctly():
    analyzer = AnalyzerWithResources()
    result = run_resource_analysis(analyzer, SilentLogger())
    assert result["total_resources"] == 3


def test_run_resource_analysis_calls_all_helper_methods():
    analyzer = AnalyzerWithResources()
    run_resource_analysis(analyzer, SilentLogger())
    expected = {
        "analyze_resource_types",
        "extract_version_info",
        "extract_manifest",
        "extract_icons",
        "extract_strings",
        "calculate_statistics",
        "check_suspicious_resources",
    }
    assert set(analyzer.calls) == expected


def test_run_resource_analysis_populates_resources_list():
    analyzer = AnalyzerWithResources()
    result = run_resource_analysis(analyzer, SilentLogger())
    assert len(result["resources"]) == 3


# ---------------------------------------------------------------------------
# Tests – empty resource list returned from _parse_resources (lines 39-40)
# ---------------------------------------------------------------------------


def test_run_resource_analysis_has_resources_but_empty_parse():
    analyzer = AnalyzerWithEmptyResources()
    result = run_resource_analysis(analyzer, SilentLogger())
    assert result["has_resources"] is True
    assert result["total_resources"] == 0
    assert result["resources"] == []


# ---------------------------------------------------------------------------
# Tests – exception handler path (lines 61-66)
# ---------------------------------------------------------------------------


def test_run_resource_analysis_handles_exception_in_parse():
    analyzer = AnalyzerRaisingOnParse()
    result = run_resource_analysis(analyzer, SilentLogger())
    assert result["available"] is False
    assert result["has_resources"] is False
    assert "error" in result
    assert "parse failed" in result["error"]
