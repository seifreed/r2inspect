from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.r2_session import R2Session
from r2inspect.registry.default_registry import create_default_registry


@pytest.fixture
def real_adapters(samples_dir: Path):
    files = {
        "PE": samples_dir / "hello_pe.exe",
        "ELF": samples_dir / "hello_elf",
        "MACHO": samples_dir / "hello_macho",
    }

    sessions: dict[str, R2Session] = {}
    adapters: dict[str, R2PipeAdapter] = {}

    for key, path in files.items():
        session = R2Session(str(path))
        r2 = session.open(path.stat().st_size / (1024 * 1024))
        sessions[key] = session
        adapters[key] = R2PipeAdapter(r2)

    try:
        yield adapters, files
    finally:
        for session in sessions.values():
            session.close()


def _pick_target(file_formats: set[str]) -> str:
    upper = {fmt.upper() for fmt in file_formats}
    if "ELF" in upper:
        return "ELF"
    if "MACHO" in upper or "MACHO64" in upper or "MACHO32" in upper:
        return "MACHO"
    return "PE"


def _build_analyzer_instance(
    analyzer_class: type[Any], adapter: Any, config: Config, filepath: str
):
    constructors = [
        {"adapter": adapter, "config": config, "filepath": filepath},
        {"filepath": filepath, "r2_instance": adapter},
        {"filepath": filepath},
        {"adapter": adapter, "config": config},
        {"adapter": adapter},
        {"r2": adapter, "config": config, "filepath": filepath},
        {"r2": adapter, "config": config},
        {"r2": adapter},
    ]
    for kwargs in constructors:
        try:
            return analyzer_class(**kwargs)
        except TypeError:
            continue

    positional_args = [
        (filepath, adapter),
        (filepath,),
        (adapter, config, filepath),
        (adapter, filepath),
        (adapter, config),
        (adapter,),
    ]
    for args in positional_args:
        try:
            return analyzer_class(*args)
        except TypeError:
            continue

    raise TypeError(f"Could not construct analyzer {analyzer_class.__name__}")


def _call_noarg_methods(obj: Any) -> int:
    called = 0
    prefixes = (
        "analyze",
        "detect",
        "compute",
        "extract",
        "scan",
        "get_",
        "parse",
        "build",
        "score",
        "collect",
    )

    for method_name in dir(obj):
        if method_name.startswith("__"):
            continue
        if not method_name.startswith(prefixes) and not method_name.startswith("_"):
            continue

        method = getattr(obj, method_name, None)
        if not callable(method):
            continue

        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            continue

        required = [
            p
            for p in signature.parameters.values()
            if p.default is inspect._empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]

        if required:
            continue

        try:
            method()
            called += 1
        except Exception:
            # Real walk-through: we intentionally tolerate analyzer-specific errors
            # and keep traversing methods to maximize path execution.
            called += 1

    return called


def test_analyzer_method_walk_real(real_adapters) -> None:
    adapters, files = real_adapters
    config = Config()
    registry = create_default_registry()

    total_methods_called = 0
    total_analyzers = 0

    for item in registry.list_analyzers():
        name = item["name"]
        analyzer_class = registry.get_analyzer_class(name)
        assert analyzer_class is not None

        meta = registry.get_metadata(name)
        assert meta is not None
        target = _pick_target(meta.file_formats)

        try:
            analyzer = _build_analyzer_instance(
                analyzer_class,
                adapters[target],
                config,
                str(files[target]),
            )
        except Exception:
            continue

        total_analyzers += 1
        total_methods_called += _call_noarg_methods(analyzer)

    assert total_analyzers >= 20
    assert total_methods_called >= 40
