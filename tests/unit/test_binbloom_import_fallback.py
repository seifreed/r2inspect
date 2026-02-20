"""Test ImportError fallback in binbloom_analyzer.py using sys.modules manipulation."""

from __future__ import annotations

import importlib
import sys

import pytest


def test_binbloom_import_fallback_sets_bloom_unavailable():
    """Test that ImportError is handled and sets BLOOM_AVAILABLE to False."""
    module_name = "r2inspect.modules.binbloom_analyzer"

    # Save original sys.modules state
    saved_modules = {}
    modules_to_remove = [module_name, "pybloom_live"]
    for name in modules_to_remove:
        if name in sys.modules:
            saved_modules[name] = sys.modules[name]

    try:
        # Remove the module and pybloom_live to simulate import failure
        for name in modules_to_remove:
            if name in sys.modules:
                del sys.modules[name]

        # Block pybloom_live import by setting it to None in sys.modules
        sys.modules["pybloom_live"] = None

        # Now import the binbloom_analyzer module (should trigger ImportError handling)
        binbloom = importlib.import_module(module_name)

        # Verify the fallback was triggered
        assert binbloom.BLOOM_AVAILABLE is False
        assert binbloom.BloomFilter is None
    finally:
        # Restore original sys.modules state
        if "pybloom_live" in sys.modules:
            del sys.modules["pybloom_live"]

        if module_name in sys.modules:
            del sys.modules[module_name]

        for name, module in saved_modules.items():
            sys.modules[name] = module

        # Re-import to restore normal state
        importlib.import_module(module_name)
