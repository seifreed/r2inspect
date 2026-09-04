from __future__ import annotations

import builtins

import pytest

from r2inspect.testing.module_loading import blocked_import, import_fresh


def test_module_loading_helpers_restore_import_state() -> None:
    assert import_fresh("json").loads("{}") == {}
    original = builtins.__import__
    with blocked_import("blocked_module"):
        with pytest.raises(ImportError, match="forced import failure"):
            __import__("blocked_module")
        assert __import__("json")
    assert builtins.__import__ is original
