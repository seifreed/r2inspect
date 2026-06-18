from __future__ import annotations

from r2inspect.modules.resource_support import _resource_debug_name


def test_resource_debug_name_prefers_name_then_type_then_unknown() -> None:
    assert _resource_debug_name({"name": "icon"}) == "icon"
    assert _resource_debug_name({"name": None, "type_name": "RT_ICON"}) == "RT_ICON"  # type: ignore[arg-type]
    assert _resource_debug_name({"name": None, "type_name": None}) == "UNKNOWN"  # type: ignore[arg-type]
