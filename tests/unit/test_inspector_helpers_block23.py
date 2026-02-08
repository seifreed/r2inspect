from __future__ import annotations

from r2inspect.core.inspector import R2Inspector


def test_inspector_helpers():
    assert R2Inspector._as_dict({"a": 1}) == {"a": 1}
    assert R2Inspector._as_dict(None) == {}

    assert R2Inspector._as_bool_dict({"a": True}) == {"a": True}
    assert R2Inspector._as_bool_dict({"a": "no"}) == {"a": True}
    assert R2Inspector._as_bool_dict({"a": 0}) == {"a": False}
    assert R2Inspector._as_bool_dict(None) == {}

    assert R2Inspector._as_str("ok") == "ok"
    assert R2Inspector._as_str(123, default="x") == "x"
