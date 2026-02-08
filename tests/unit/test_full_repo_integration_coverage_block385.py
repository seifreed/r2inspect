from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from r2inspect.__main__ import main as package_main
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
        file_size_mb = path.stat().st_size / (1024 * 1024)
        r2 = session.open(file_size_mb)
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


def _build_analyzer_instance(analyzer_class, adapter, config, filepath: str):
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


def _run_analyzer_instance(analyzer):
    for method_name in ("analyze", "detect", "detect_compiler", "scan"):
        method = getattr(analyzer, method_name, None)
        if callable(method):
            return method()
    for method_name in dir(analyzer):
        if method_name.startswith("_"):
            continue
        if not (
            method_name.startswith("analyze")
            or method_name.startswith("detect")
            or method_name.startswith("compute")
            or method_name.startswith("run")
            or method_name.startswith("scan")
        ):
            continue
        method = getattr(analyzer, method_name, None)
        if not callable(method):
            continue
        signature = inspect.signature(method)
        required = [
            p
            for p in signature.parameters.values()
            if p.default is inspect._empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        if not required:
            return method()
    raise AttributeError(f"No executable analysis method found for {type(analyzer).__name__}")


def test_main_entrypoint_real_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["r2inspect", "--help"])
    assert package_main() == 0


def test_all_registered_analyzers_run_real(real_adapters) -> None:
    adapters, files = real_adapters
    config = Config()
    registry = create_default_registry()

    executed = 0

    names = sorted(item["name"] for item in registry.list_analyzers())
    for name in names:
        analyzer_class = registry.get_analyzer_class(name)
        assert analyzer_class is not None

        meta = registry.get_metadata(name)
        assert meta is not None
        target = _pick_target(meta.file_formats)

        analyzer = _build_analyzer_instance(
            analyzer_class,
            adapters[target],
            config,
            str(files[target]),
        )
        result = _run_analyzer_instance(analyzer)

        assert isinstance(result, (dict, list))
        assert result is not None
        executed += 1

    assert executed >= 20
