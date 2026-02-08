from __future__ import annotations

import importlib

version_module = importlib.import_module("r2inspect.__version__")


def test_version_metadata_present():
    assert isinstance(version_module.__version__, str)
    assert version_module.__version__
    assert isinstance(version_module.__author__, str)
    assert version_module.__author__
    assert isinstance(version_module.__author_email__, str)
    assert "@" in version_module.__author_email__
    assert isinstance(version_module.__license__, str)
    assert version_module.__license__
    assert isinstance(version_module.__url__, str)
    assert version_module.__url__.startswith("https://")
