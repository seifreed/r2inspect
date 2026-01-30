#!/usr/bin/env python3
"""
Bottleneck Analysis - Identify performance issues

Copyright (C) 2025 Marc Rivero López
Licensed under GPLv3
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def time_import(description, import_fn):
    """Time a specific import"""
    import gc
    import sys

    # Clear the import
    modules_to_remove = [k for k in sys.modules if "r2inspect" in k]
    for module in modules_to_remove:
        del sys.modules[module]
    gc.collect()

    start = time.perf_counter()
    import_fn()
    elapsed = time.perf_counter() - start

    print(f"{description:50s}: {elapsed * 1000:8.2f} ms")
    return elapsed * 1000


def main():
    _print_header()
    _run_import_timings()
    analyzer_modules = _report_loaded_modules()
    _report_heavy_deps(analyzer_modules)


def _print_header() -> None:
    print("=" * 80)
    print("BOTTLENECK ANALYSIS")
    print("=" * 80)
    print()


def _run_import_timings() -> None:
    print("Individual Import Times:")
    print("-" * 80)
    time_import("Empty import", lambda: None)
    time_import("import pathlib", lambda: __import__("pathlib"))
    time_import("import r2pipe", lambda: __import__("r2pipe"))
    time_import("import rich", lambda: __import__("rich"))
    time_import("from r2inspect import __version__", lambda: __import__("r2inspect"))
    time_import(
        "from r2inspect.config import Config",
        lambda: __import__("r2inspect.config", fromlist=["Config"]),
    )
    time_import(
        "from r2inspect.registry import AnalyzerRegistry",
        lambda: __import__("r2inspect.registry", fromlist=["AnalyzerRegistry"]),
    )
    print("\nThe Problematic Import:")
    print("-" * 80)
    time_import("from r2inspect import modules", lambda: __import__("r2inspect.modules"))
    print("\nFull Import:")
    print("-" * 80)
    time_import(
        "from r2inspect import R2Inspector",
        lambda: __import__("r2inspect", fromlist=["R2Inspector"]),
    )


def _report_loaded_modules() -> list[str]:
    print("\n" + "=" * 80)
    print("ANALYSIS")
    print("=" * 80)

    import sys

    from r2inspect import R2Inspector  # noqa: F401

    r2inspect_modules = [m for m in sys.modules if "r2inspect" in m]
    analyzer_modules = [
        m for m in r2inspect_modules if "r2inspect.modules." in m and not m.endswith("__init__")
    ]

    print(f"\nTotal r2inspect modules loaded: {len(r2inspect_modules)}")
    print(f"Analyzer modules loaded:        {len(analyzer_modules)}")
    print("\nAnalyzer modules:")
    for mod in sorted(analyzer_modules):
        print(f"  {mod}")
    return analyzer_modules


def _report_heavy_deps(analyzer_modules: list[str]) -> None:
    print("\n" + "=" * 80)
    print("HEAVY DEPENDENCIES IN ANALYZER MODULES")
    print("=" * 80)
    heavy_deps = _find_heavy_deps(analyzer_modules)
    for analyzer, deps in sorted(heavy_deps.items()):
        print(f"{analyzer:30s}: {', '.join(deps)}")


def _find_heavy_deps(analyzer_modules: list[str]) -> dict[str, list[str]]:
    import sys

    heavy_deps: dict[str, list[str]] = {}
    heavy_pkg_markers = [
        "numpy",
        "pefile",
        "yara",
        "ssdeep",
        "tlsh",
        "simhash",
    ]
    for mod in analyzer_modules:
        module_obj = sys.modules.get(mod)
        if not _module_has_file(module_obj):
            continue
        deps = _collect_heavy_deps(sys.modules, heavy_pkg_markers)
        if deps:
            heavy_deps[mod.split(".")[-1]] = list(set(deps))
    return heavy_deps


def _module_has_file(module_obj) -> bool:
    return bool(module_obj and hasattr(module_obj, "__file__"))


def _collect_heavy_deps(modules: dict[str, object], heavy_pkg_markers: list[str]) -> list[str]:
    deps: list[str] = []
    for dep_name, dep_mod in modules.items():
        if not _is_site_package(dep_mod):
            continue
        if _is_heavy_dep(dep_name, heavy_pkg_markers):
            deps.append(dep_name.split(".")[0])
    return deps


def _is_site_package(dep_mod: object) -> bool:
    if not dep_mod or not hasattr(dep_mod, "__file__"):
        return False
    return bool(dep_mod.__file__ and "site-packages" in str(dep_mod.__file__))


def _is_heavy_dep(dep_name: str, heavy_pkg_markers: list[str]) -> bool:
    return any(pkg in dep_name for pkg in heavy_pkg_markers)


if __name__ == "__main__":
    main()
