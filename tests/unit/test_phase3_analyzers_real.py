from __future__ import annotations

from typing import Any

from r2inspect.modules.function_analyzer import FunctionAnalyzer, _normalize_function_list
from r2inspect.modules.resource_analyzer import ResourceAnalyzer, run_resource_analysis
from tests.helpers import FakeR2Adapter


class CaptureLogger:
    def __init__(self) -> None:
        self.debug_messages: list[str] = []
        self.error_messages: list[str] = []

    def debug(self, message: str, *args: object) -> None:
        self.debug_messages.append(message % args if args else message)

    def error(self, message: str, *args: object) -> None:
        self.error_messages.append(message % args if args else message)


class FunctionAdapter(FakeR2Adapter):
    def __init__(self) -> None:
        super().__init__(
            cmd_responses={
                "aa": "ok",
                "aaa": "ok",
                "pi 100 @ 4096": "0x401000 mov eax, ebx\n0x401005 ret",
            },
            cmdj_responses={
                "aflj": "not-a-list",
                "agj @ 4096": {"blocks": [{"size": 1}, {"size": 1}]},
            },
        )

    def get_cfg(self, _address: int) -> dict[str, Any]:
        return {"blocks": [{"jump": 1}, {"fail": 2}]}


class ResourceAdapter:
    def __init__(self, cmdj_responses: dict[str, Any]) -> None:
        self._cmdj_responses = cmdj_responses

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        return self._cmdj_responses.get(command, default)


def test_run_resource_analysis_real_with_non_list_resources_and_top_level_error() -> None:
    class _AnalyzerWithBadResources:
        def _init_result_structure(self, payload: dict[str, Any]) -> dict[str, Any]:
            return payload

        def _get_resource_directory(self) -> dict[str, Any]:
            return {"offset": 1, "size": 2, "virtual_address": 3}

        def _parse_resources(self) -> str:
            return "bad-shape"

    logger = CaptureLogger()
    result = run_resource_analysis(_AnalyzerWithBadResources(), logger)
    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0
    assert any("no valid resource entries" in msg for msg in logger.debug_messages)

    class _AnalyzerExplodes:
        def _init_result_structure(self, _payload: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("forced resource analysis failure")

    failed = run_resource_analysis(_AnalyzerExplodes(), logger)
    assert failed["available"] is False
    assert failed["has_resources"] is False
    assert failed["error"] == "forced resource analysis failure"
    assert any("forced resource analysis failure" in msg for msg in logger.error_messages)


def test_resource_analyzer_real_flow_and_embedded_pe_invalid_offset() -> None:
    adapter = ResourceAdapter(
        {
            "iDj": [{"name": "RESOURCE", "vaddr": 4096, "paddr": 512, "size": 2048}],
            "iRj": [
                {
                    "name": "APPMANIFEST",
                    "type": "RT_MANIFEST",
                    "type_id": 24,
                    "lang": "en",
                    "paddr": 100,
                    "size": 64,
                    "vaddr": 4100,
                },
                {
                    "name": "HELLO",
                    "type": "RT_STRING",
                    "type_id": 6,
                    "lang": "en",
                    "paddr": 200,
                    "size": 32,
                    "vaddr": 4200,
                },
                {
                    "name": "PAYLOAD",
                    "type": "RT_RCDATA",
                    "type_id": 10,
                    "lang": "en",
                    "paddr": 300,
                    "size": 2048,
                    "vaddr": 4300,
                },
            ],
            "pxj 64 @ 100": list(
                b'<?xml version="1.0"?><requestedExecutionLevel level="requireAdministrator"/>'
            ),
            "pxj 32 @ 200": list("Hello\x00World\x00".encode("utf-16le")),
            "pxj 2048 @ 300": [0x4D, 0x5A] + [0] * 2046,
            "pxj 2 @ 300": [0x4D, 0x5A],
        }
    )
    analyzer = ResourceAnalyzer(adapter)

    result = analyzer.analyze()

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 3
    assert result["manifest"]["requires_admin"] is True
    assert any("Hello" in value for value in result["strings"])
    assert result["suspicious_resources"]
    assert (
        analyzer._check_resource_embedded_pe({"type_name": "RT_ICON", "size": 2048, "offset": 300})
        == []
    )
    assert (
        analyzer._check_resource_embedded_pe(
            {"type_name": "RT_RCDATA", "size": "bad", "offset": 300}
        )
        == []
    )
    assert (
        analyzer._check_resource_embedded_pe(
            {"type_name": "RT_RCDATA", "size": 2048, "offset": "abc"}
        )
        == []
    )
    assert (
        analyzer._check_resource_embedded_pe({"type_name": "RT_RCDATA", "size": 12, "offset": 300})
        == []
    )


def test_function_analyzer_real_normalization_and_exception_branches() -> None:
    analyzer = FunctionAnalyzer(FunctionAdapter())

    assert _normalize_function_list("bad-shape") == []
    functions = analyzer._get_functions()
    assert functions == []
    assert analyzer.functions_cache == []
    assert analyzer._classify_function_type(None, {}) == "unknown"  # type: ignore[arg-type]
    assert analyzer._classify_function_type("entry", None) == "unknown"  # type: ignore[arg-type]
    assert analyzer._calculate_cyclomatic_complexity({"addr": 0x1000}) >= 0
    assert analyzer._extract_function_mnemonics("entry", 10, 4096) == ["mov", "ret"]


def test_run_resource_analysis_real_without_resource_directory() -> None:
    class _AnalyzerWithoutDirectory:
        def _init_result_structure(self, payload: dict[str, Any]) -> dict[str, Any]:
            return payload

        def _get_resource_directory(self) -> None:
            return None

    logger = CaptureLogger()
    result = run_resource_analysis(_AnalyzerWithoutDirectory(), logger)
    assert result["available"] is True
    assert result["has_resources"] is False
