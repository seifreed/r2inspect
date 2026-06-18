from __future__ import annotations

import importlib
import pathlib
import tomllib

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


def test_runtime_version_matches_package_metadata():
    pyproject = pathlib.Path(__file__).parents[2] / "pyproject.toml"
    metadata = tomllib.loads(pyproject.read_text())

    assert version_module.__version__ == metadata["project"]["version"]
