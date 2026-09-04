"""Conformance checks for third-party analyzer plugins."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
from collections.abc import Callable
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from ..abstractions import BaseAnalyzer
from ..core.analyzer_factory import create_analyzer
from ..registry import AnalyzerRegistry, AnalyzerSpec

SCHEMA_VERSION = "r2inspect.plugin-conformance/v1"


def _check(check_id: str, passed: bool, message: str) -> dict[str, str]:
    return {"id": check_id, "status": "passed" if passed else "failed", "message": message}


def _registered_classes(provider: Callable[..., Any]) -> list[tuple[str, type[Any]]]:
    registry = AnalyzerRegistry(lazy_loading=False)
    provider(registry)
    resolved = []
    for metadata in registry.list_analyzers():
        name = str(metadata["name"])
        analyzer_class = registry.get_analyzer_class(name)
        if analyzer_class is not None:
            resolved.append((name, analyzer_class))
    if not resolved:
        raise ValueError("plugin provider did not register any analyzers")
    return resolved


def load_plugin(
    target: str, entry_points_fn: Callable[[], Any] = entry_points
) -> list[tuple[str, type[Any]]]:
    """Load analyzer classes from ``module:Class`` or an installed entry point."""
    if ":" in target:
        module_name, attribute = target.split(":", 1)
        obj = getattr(importlib.import_module(module_name), attribute)
    else:
        matches = list(entry_points_fn().select(group="r2inspect.analyzers", name=target))
        if len(matches) != 1:
            raise ValueError(f"expected one r2inspect.analyzers entry point named {target!r}")
        obj = matches[0].load()
    if inspect.isclass(obj):
        return [(target, obj)]
    if callable(obj):
        return _registered_classes(obj)
    raise TypeError("plugin target must be an analyzer class or registry provider")


def check_analyzer_class(
    analyzer_class: type[Any], *, name: str | None = None, sample: Path | None = None
) -> dict[str, Any]:
    """Check one analyzer against the public plugin contract."""
    analyzer_name = name or analyzer_class.__name__
    registry = AnalyzerRegistry(lazy_loading=False)
    valid, error = registry.validate_analyzer(analyzer_class)
    inherits_base = inspect.isclass(analyzer_class) and issubclass(analyzer_class, BaseAnalyzer)
    checks = [
        _check("analyzer_class", valid, error or "analyzer class is structurally valid"),
        _check(
            "base_analyzer",
            inherits_base,
            "inherits BaseAnalyzer" if inherits_base else "must inherit BaseAnalyzer",
        ),
    ]
    spec = getattr(analyzer_class, "spec", None)
    checks.append(
        _check(
            "analyzer_spec",
            isinstance(spec, AnalyzerSpec),
            "declares AnalyzerSpec" if isinstance(spec, AnalyzerSpec) else "missing AnalyzerSpec",
        )
    )
    analyzer: Any = None
    try:
        analyzer = create_analyzer(
            analyzer_class,
            adapter=object(),
            config={},
            filename=str(sample or Path("sample.bin")),
        )
    except Exception as exc:
        checks.append(_check("construction", False, str(exc)))
    else:
        checks.append(_check("construction", True, "constructed through the runtime factory"))
    if sample is not None and analyzer is not None:
        try:
            output = analyzer.analyze()
            if not isinstance(output, dict):
                raise TypeError("analyze() must return a mapping")
            json.dumps(output)
        except Exception as exc:
            checks.append(_check("sample_execution", False, str(exc)))
        else:
            checks.append(_check("sample_execution", True, "output is JSON-compatible"))
    passed = all(check["status"] == "passed" for check in checks)
    return {"analyzer": analyzer_name, "status": "passed" if passed else "failed", "checks": checks}


def check_plugin(target: str, *, sample: Path | None = None) -> dict[str, Any]:
    """Load and validate every analyzer exposed by a plugin target."""
    analyzers = load_plugin(target)
    results = [check_analyzer_class(cls, name=name, sample=sample) for name, cls in analyzers]
    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "status": "passed" if all(item["status"] == "passed" for item in results) else "failed",
        "analyzers": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate an r2inspect analyzer plugin")
    parser.add_argument("target", help="module:Class or r2inspect.analyzers entry-point name")
    parser.add_argument("--sample", type=Path, help="optionally execute against a sample")
    args = parser.parse_args()
    try:
        if args.sample is not None and not args.sample.is_file():
            raise ValueError(f"sample is not a file: {args.sample}")
        result = check_plugin(args.target, sample=args.sample)
    except (AttributeError, ImportError, TypeError, ValueError) as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "target": args.target,
            "status": "failed",
            "error": str(exc),
            "analyzers": [],
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "passed":
        raise SystemExit(1)


__all__ = ["SCHEMA_VERSION", "check_analyzer_class", "check_plugin", "load_plugin", "main"]
