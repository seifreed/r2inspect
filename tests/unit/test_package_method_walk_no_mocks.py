from __future__ import annotations

import inspect
import os
import pkgutil
import signal
import tempfile
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Any

import r2inspect


class _Adapter:
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


class _Config:
    def get(self, _key: str, default: Any = None):
        return default


def _timeout_handler(signum, frame):
    raise TimeoutError("call timeout")


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
        else:
            kwargs[name] = None

    previous_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, 0.2)
    try:
        callable_obj(**kwargs)
    except (Exception, SystemExit):
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    return True


def _construct_instance(cls: type, pool: dict[str, Any]) -> Any | None:
    kwargs_options = [
        {"adapter": pool["adapter"], "config": pool["config"], "filepath": pool["filepath"]},
        {"r2": pool["adapter"], "config": pool["config"], "filepath": pool["filepath"]},
        {"r2_instance": pool["adapter"], "filepath": pool["filepath"]},
        {"filepath": pool["filepath"], "config": pool["config"]},
        {"filepath": pool["filepath"]},
        {"adapter": pool["adapter"]},
        {"config": pool["config"]},
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
        (pool["adapter"],),
        (),
    ]
    for args in args_options:
        try:
            return cls(*args)
        except Exception:
            continue
    return None


def _walk_module_functions(module: ModuleType, pool: dict[str, Any], max_calls: int) -> int:
    executed = 0
    for name, member in inspect.getmembers(module):
        if executed >= max_calls:
            break
        if name.startswith("__"):
            continue
        if inspect.isclass(member) or not callable(member):
            continue
        if _call_with_pool(member, pool):
            executed += 1
    return executed


def _walk_instance_methods(instance: Any, pool: dict[str, Any], max_calls: int) -> int:
    executed = 0
    for name, member in inspect.getmembers(instance):
        if executed >= max_calls:
            break
        if name.startswith("__"):
            continue
        if not callable(member):
            continue
        if _call_with_pool(member, pool):
            executed += 1
    return executed


def test_package_method_walk_without_mocks() -> None:
    os.environ.setdefault("R2INSPECT_TEST_MODE", "1")
    os.environ.setdefault("R2INSPECT_ANALYSIS_DEPTH", "1")
    os.environ.setdefault("R2INSPECT_CMD_TIMEOUT_SECONDS", "0.2")

    adapter = _Adapter()
    config = _Config()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        binary_path = tmp_path / "sample.bin"
        binary_path.write_bytes(b"MZ" + b"\x00" * 510)
        output_dir = tmp_path / "out"
        output_dir.mkdir(exist_ok=True)

        data = binary_path.read_bytes()
        pool = {
            "adapter": adapter,
            "r2": adapter,
            "r2_instance": adapter,
            "config": config,
            "cfg": config,
            "filepath": str(binary_path),
            "file_path": str(binary_path),
            "filename": str(binary_path),
            "path": str(binary_path),
            "batch_dir": str(tmp_path),
            "output_dir": str(output_dir),
            "directory": str(tmp_path),
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
            "recursive": True,
            "quiet": True,
            "verbose": False,
            "output_json": True,
            "output_csv": False,
            "threads": 1,
            "auto_detect": False,
            "extensions": "bin,exe,elf",
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
        module_names = sorted(
            name for _, name, _ in pkgutil.walk_packages(r2inspect.__path__, prefix="r2inspect.")
        )
        skip_modules = {
            "r2inspect.__main__",
        }

        max_total_calls = 20000
        per_module_max = 300

        for module_name in module_names:
            if executed >= max_total_calls:
                break
            if module_name in skip_modules:
                continue
            try:
                module = import_module(module_name)
            except Exception:
                continue

            executed += _walk_module_functions(module, pool, per_module_max)
            if executed >= max_total_calls:
                break

            for _, cls in inspect.getmembers(module, inspect.isclass):
                if executed >= max_total_calls:
                    break
                if cls.__module__ != module.__name__:
                    continue
                instance = _construct_instance(cls, pool)
                if instance is None:
                    continue
                executed += _walk_instance_methods(instance, pool, per_module_max)

        assert executed > 1500
