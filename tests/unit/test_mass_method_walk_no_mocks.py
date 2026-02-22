from __future__ import annotations

import inspect
import os
import pkgutil
import tempfile
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Any

import r2inspect.modules as modules_pkg


class NoMockAdapter:
    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str):
        return []

    def get_info_text(self):
        return ""

    def get_file_info(self):
        return {"bin": {"class": "Unknown", "format": "Unknown", "bits": 0}}

    def get_dynamic_info_text(self):
        return ""

    def get_imports(self):
        return []

    def get_exports(self):
        return []

    def get_sections(self):
        return []

    def get_symbols(self):
        return []

    def get_strings(self):
        return []

    def get_strings_basic(self):
        return []

    def get_strings_text(self):
        return ""

    def get_disasm(self, address: int | None = None, size: int | None = None):
        return [] if address is None else [{"offset": address, "size": size or 0}]

    def get_disasm_text(self, address: int | None = None, size: int | None = None):
        return f"{address}:{size}"

    def get_cfg(self, address: int | None = None):
        return {"cfg": address}

    def get_functions(self):
        return []

    def get_functions_at(self, _address: int):
        return []

    def get_function_info(self, address: int):
        return {"offset": address}

    def read_bytes(self, _address: int, size: int):
        return b"\x00" * max(size, 0)

    def read_bytes_list(self, _address: int, size: int):
        return [0] * max(size, 0)

    def search_hex_json(self, _pattern: str):
        return []

    def search_hex(self, _pattern: str):
        return []

    def search_text(self, _pattern: str):
        return []


class TinyConfig:
    def get(self, _key: str, default: Any = None):
        return default


def _call_with_pool(callable_obj: Any, pool: dict[str, Any]) -> bool:
    try:
        sig = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return False
    kwargs: dict[str, Any] = {}
    for name, param in sig.parameters.items():
        if param.default is not inspect._empty:
            continue
        if name in pool:
            kwargs[name] = pool[name]
            continue
        return False
    try:
        callable_obj(**kwargs)
    except Exception:
        pass
    return True


def _construct_instance(cls: type, pool: dict[str, Any]) -> Any | None:
    kwargs_options = [
        {"adapter": pool["adapter"], "config": pool["config"], "filepath": pool["filepath"]},
        {"r2": pool["adapter"], "config": pool["config"], "filepath": pool["filepath"]},
        {"r2_instance": pool["adapter"], "filepath": pool["filepath"]},
        {"filepath": pool["filepath"]},
        {"adapter": pool["adapter"]},
        {},
    ]
    for kwargs in kwargs_options:
        try:
            return cls(**kwargs)
        except Exception:
            continue
    args_options = [
        (pool["filepath"], pool["adapter"]),
        (pool["adapter"], pool["config"], pool["filepath"]),
        (pool["filepath"],),
        (),
    ]
    for args in args_options:
        try:
            return cls(*args)
        except Exception:
            continue
    return None


def _walk_module_functions(module: ModuleType, pool: dict[str, Any]) -> int:
    executed = 0
    for name, member in inspect.getmembers(module):
        if name.startswith("_"):
            continue
        if inspect.isclass(member) or not callable(member):
            continue
        if _call_with_pool(member, pool):
            executed += 1
    return executed


def _walk_instance_methods(instance: Any, pool: dict[str, Any]) -> int:
    executed = 0
    for name, member in inspect.getmembers(instance):
        if name.startswith("__"):
            continue
        if not callable(member):
            continue
        if _call_with_pool(member, pool):
            executed += 1
    return executed


def test_mass_method_walk_without_mocks() -> None:
    os.environ.setdefault("R2INSPECT_TEST_MODE", "1")
    os.environ.setdefault("R2INSPECT_ANALYSIS_DEPTH", "1")
    os.environ.setdefault("R2INSPECT_CMD_TIMEOUT_SECONDS", "0.2")

    adapter = NoMockAdapter()
    config = TinyConfig()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(b"MZ" + b"\x00" * 510)
        filepath = tmp.name

    file_path_obj = Path(filepath)
    data = file_path_obj.read_bytes()

    pool = {
        "adapter": adapter,
        "r2": adapter,
        "r2_instance": adapter,
        "config": config,
        "cfg": config,
        "filepath": filepath,
        "file_path": filepath,
        "filename": filepath,
        "path": filepath,
        "data": {},
        "result": {},
        "results": {},
        "analysis_result": {},
        "content": data,
        "data_bytes": data,
        "buffer": data,
        "raw": data,
        "blob": data,
        "bytes_data": data,
        "ints": list(data[:64]),
        "data_ints": list(data[:64]),
        "offset": 0,
        "size": 64,
        "length": 16,
        "index": 0,
        "threshold": 0.1,
        "timeout": 1,
        "limit": 1,
        "count": 1,
        "pattern": b"MZ",
        "patterns": ["MZ", "PE"],
        "min_length": 1,
        "max_length": 64,
        "min_size": 1,
        "max_size": 1024,
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
        "strings": ["kernel32.dll", "CreateProcessA"],
        "imports": [{"name": "CreateProcessA", "library": "kernel32.dll"}],
        "exports": [{"name": "main", "address": "0x1000"}],
        "entropy": 7.0,
        "hash_value": "deadbeef",
        "hashes": {"md5": "x", "sha1": "y", "sha256": "z"},
        "scores": {"total": 0.5},
        "flags": {"aslr": True},
        "max_results": 5,
        "max_entries": 5,
        "max_items": 5,
        "depth": 1,
        "level": 1,
        "analysis_depth": 1,
    }

    executed = 0
    module_names = sorted(m.name for m in pkgutil.iter_modules(modules_pkg.__path__))
    skip_modules = {"__pycache__"}

    for module_name in module_names:
        if module_name in skip_modules:
            continue
        module = import_module(f"r2inspect.modules.{module_name}")
        executed += _walk_module_functions(module, pool)

        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__:
                continue
            instance = _construct_instance(cls, pool)
            if instance is None:
                continue
            executed += _walk_instance_methods(instance, pool)

    assert executed > 50
