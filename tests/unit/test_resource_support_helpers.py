from __future__ import annotations

from typing import Any

from r2inspect.modules.resource_support import (
    _resource_debug_name,
    analyze_resource_data,
    check_suspicious_resources,
    extract_manifest,
    extract_strings,
    extract_version_info,
    read_resource_as_string,
)


class _Host:
    def debug(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def _cmdj(self, command: str, default: Any | None = None) -> Any:
        return default

    def _calculate_entropy(self, data: list[int]) -> float:
        return 0.0

    def _parse_version_info(self, offset: int, size: int) -> dict[str, Any] | None:
        return None

    def _read_resource_as_string(self, offset: int, size: int) -> str | None:
        return None

    def _read_version_info_data(self, offset: int, size: int) -> list[int] | None:
        return None

    def _find_vs_signature(self, data: list[int]) -> int:
        return -1

    def _parse_fixed_file_info(self, data: list[int], sig_pos: int) -> str:
        return ""

    def _extract_version_strings(self, data: list[int]) -> dict[str, str]:
        return {}


def test_resource_debug_name_prefers_name_then_type_then_unknown() -> None:
    assert _resource_debug_name({"name": "icon"}) == "icon"
    assert _resource_debug_name({"name": None, "type_name": "RT_ICON"}) == "RT_ICON"  # type: ignore[arg-type]
    assert _resource_debug_name({"name": None, "type_name": None}) == "UNKNOWN"  # type: ignore[arg-type]


def test_resource_support_helpers_skip_non_dict_resource_entries() -> None:
    host = _Host()
    result: dict[str, Any] = {}
    resources: list[Any] = ["bad", {"type_name": "RT_VERSION"}, None]

    analyze_resource_data(host, "bad", logger=host, calculate_hashes_for_bytes=lambda _: {})  # type: ignore[arg-type]
    extract_version_info(host, result, resources, logger=host)  # type: ignore[arg-type]
    extract_manifest(host, result, resources, logger=host)  # type: ignore[arg-type]
    extract_strings(host, result, resources, logger=host, split_null_terminated=lambda *args, **kwargs: [])  # type: ignore[arg-type]

    assert result == {"strings": []}


def test_resource_support_helpers_reject_dict_payloads() -> None:
    class _DictPayloadHost(_Host):
        def __init__(self) -> None:
            self.commands: list[str] = []

        def _cmdj(self, command: str, default: Any | None = None) -> Any:
            self.commands.append(command)
            if command.startswith("pxj "):
                return {"bytes": [0x41, 0x42]}
            return default

    host = _DictPayloadHost()
    resource: dict[str, Any] = {"offset": 0x1000, "size": 2}
    analyze_resource_data(host, resource, logger=host, calculate_hashes_for_bytes=lambda _: {})
    assert resource["entropy"] == 0.0
    assert resource["hashes"] == {}

    assert read_resource_as_string(host, 0x1000, 2, logger=host) is None

    result: dict[str, Any] = {}
    check_suspicious_resources(host, result, [resource])
    assert result["suspicious_resources"] == []
