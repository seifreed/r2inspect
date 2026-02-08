from __future__ import annotations

import importlib
import sys

import pytest


def _reload_module(module_name: str) -> object:
    sys.modules.pop(module_name, None)
    importlib.invalidate_caches()
    return importlib.import_module(module_name)


def test_cli_init_lazy_exports_and_main() -> None:
    cli_pkg = _reload_module("r2inspect.cli")
    assert "Command" in cli_pkg.__all__

    assert cli_pkg.validators.__name__ == "r2inspect.cli.validators"
    assert callable(cli_pkg.display_results)
    assert callable(cli_pkg.display_error_statistics)
    assert callable(cli_pkg.display_performance_statistics)

    old_argv = sys.argv
    try:
        sys.argv = ["r2inspect", "--version"]
        with pytest.raises(SystemExit):
            cli_pkg.main()
    finally:
        sys.argv = old_argv


def test_schemas_init_registers() -> None:
    schemas_pkg = _reload_module("r2inspect.schemas")
    assert "HashAnalysisResult" in schemas_pkg.__all__
    assert schemas_pkg.__version__ == "1.0.0"


def test_utils_init_getattr() -> None:
    utils_pkg = _reload_module("r2inspect.utils")
    assert callable(utils_pkg.safe_cmdj)
    assert callable(utils_pkg.safe_cmd)
    with pytest.raises(AttributeError):
        _ = utils_pkg.__getattr__("missing")
