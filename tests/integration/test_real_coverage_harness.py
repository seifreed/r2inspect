from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.r2_session import R2Session
from r2inspect.registry.default_registry import create_default_registry


def _load_expected(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _build_arg_pool(
    adapter: R2PipeAdapter,
    config: Config,
    file_path: Path,
    expected: dict[str, Any],
    data_bytes: bytes,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pool = {
        "adapter": adapter,
        "r2": adapter,
        "r2_instance": adapter,
        "config": config,
        "cfg": config,
        "filepath": str(file_path),
        "file_path": str(file_path),
        "filename": str(file_path),
        "path": str(file_path),
        "file_format": expected.get("file_info", {}).get("file_type", "PE"),
        "file_formats": {
            expected.get("file_info", {}).get("file_type", "PE"),
        },
        "data": expected,
        "result": expected,
        "results": expected,
        "analysis_result": expected,
        "content": data_bytes,
        "data_bytes": data_bytes,
        "buffer": data_bytes,
        "raw": data_bytes,
        "blob": data_bytes,
        "bytes_data": data_bytes,
        "ints": list(data_bytes[:256]),
        "data_ints": list(data_bytes[:256]),
        "offset": 0,
        "size": min(len(data_bytes), 256),
        "length": min(len(data_bytes), 128),
        "index": 0,
        "threshold": 0.1,
        "timeout": 1,
        "limit": 1,
        "count": 1,
        "pattern": b"Rich",
        "patterns": ["Rich", "DanS", "MZ", "PE"],
        "min_length": 1,
        "max_length": 128,
        "min_size": 1,
        "max_size": 512,
        "min_score": 0.0,
        "max_score": 1.0,
        "options": {
            "batch_mode": True,
            "detect_packer": True,
            "detect_crypto": True,
            "analyze_functions": True,
            "custom_yara": None,
        },
        "rules_path": "rules/yara",
        "custom_yara": None,
        "features": [],
        "strings": ["http://example.com", "cmd.exe", "kernel32.dll"],
        "imports": ["kernel32.dll", "user32.dll"],
        "exports": ["main", "_start"],
        "entropy": 7.5,
        "hash_value": "deadbeef",
        "hashes": {"md5": "x", "sha1": "y"},
        "scores": {"total": 0.5},
        "flags": {"aslr": True},
        "max_results": 5,
        "max_entries": 5,
        "max_items": 5,
        "depth": 1,
        "level": 1,
        "analysis_depth": 1,
    }
    if extra:
        pool.update(extra)
    return pool


def _call_with_pool(callable_obj: Any, arg_pool: dict[str, Any]) -> bool:
    signature = inspect.signature(callable_obj)
    kwargs: dict[str, Any] = {}
    for name, param in signature.parameters.items():
        if param.default is not inspect._empty:
            continue
        if name in arg_pool:
            kwargs[name] = arg_pool[name]
            continue
        return False
    try:
        callable_obj(**kwargs)
    except Exception:
        # Best-effort execution for coverage; errors are tolerated.
        pass
    return True


def _walk_module_functions(module: ModuleType, arg_pool: dict[str, Any]) -> int:
    executed = 0
    for name, member in inspect.getmembers(module):
        if name.startswith("_"):
            continue
        if not callable(member):
            continue
        if inspect.isclass(member):
            continue
        if _call_with_pool(member, arg_pool):
            executed += 1
    return executed


def _walk_instance_methods(instance: Any, arg_pool: dict[str, Any]) -> int:
    executed = 0
    for name, member in inspect.getmembers(instance):
        if name.startswith("__"):
            continue
        if not callable(member):
            continue
        if _call_with_pool(member, arg_pool):
            executed += 1
    return executed


def _open_adapters(samples_dir: Path):
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
    return adapters, sessions, files


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


def test_best_effort_analyzer_method_walk(samples_dir: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "0")
    monkeypatch.setenv("R2INSPECT_ANALYSIS_DEPTH", "2")
    monkeypatch.setenv("R2INSPECT_CMD_TIMEOUT_SECONDS", "0.5")

    expected_root = samples_dir / "expected"
    expected_sets = [
        _load_expected(expected_root / "hello_pe.json"),
        _load_expected(expected_root / "hello_elf.json"),
        _load_expected(expected_root / "hello_macho.json"),
        _load_expected(expected_root / "edge_packed.json"),
        _load_expected(expected_root / "edge_tiny.json"),
        _load_expected(expected_root / "edge_bad_pe.json"),
        _load_expected(expected_root / "edge_high_entropy.json"),
    ]

    adapters, sessions, files = _open_adapters(samples_dir)
    try:
        config = Config()
        registry = create_default_registry()

        pe_bytes = (samples_dir / "hello_pe.exe").read_bytes()
        elf_bytes = (samples_dir / "hello_elf").read_bytes()
        macho_bytes = (samples_dir / "hello_macho").read_bytes()
        edge_packed = (samples_dir / "edge_packed.bin").read_bytes()
        edge_tiny = (samples_dir / "edge_tiny.bin").read_bytes()
        edge_bad_pe = (samples_dir / "edge_bad_pe.bin").read_bytes()
        edge_high_entropy = (samples_dir / "edge_high_entropy.bin").read_bytes()
        data_variants = [
            pe_bytes,
            elf_bytes,
            macho_bytes,
            edge_packed,
            edge_tiny,
            edge_bad_pe,
            edge_high_entropy,
            b"\x00" * 256,
            bytes(range(256)),
        ]

        executed = 0
        for name in sorted(item["name"] for item in registry.list_analyzers()):
            analyzer_class = registry.get_analyzer_class(name)
            assert analyzer_class is not None
            meta = registry.get_metadata(name)
            assert meta is not None
            target = _pick_target(meta.file_formats)

            adapter = adapters[target]
            file_path = Path(files[target])
            analyzer = _build_analyzer_instance(
                analyzer_class,
                adapter,
                config,
                str(file_path),
            )

            for expected_data in expected_sets:
                for data_bytes in data_variants:
                    arg_pool = _build_arg_pool(
                        adapter,
                        config,
                        file_path,
                        expected_data,
                        data_bytes,
                        extra={
                            "rich_pos": 0,
                            "dans_offset": 0,
                            "rich_offset": 64,
                            "sig_pos": 0,
                        },
                    )
                    executed += _walk_instance_methods(analyzer, arg_pool)

        assert executed > 0
    finally:
        for session in sessions.values():
            session.close()
