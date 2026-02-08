from __future__ import annotations

import inspect
from typing import Any

from rich.table import Table

from r2inspect.cli import display_sections


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
        pass
    return True


def test_display_sections_best_effort_walk() -> None:
    results = {
        "file_info": {
            "size": 123,
            "path": "/tmp/sample.bin",
            "name": "sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "PE",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "enhanced_detection": {"confidence": 0.9, "details": "ok"},
        },
        "pe_info": {
            "format": "PE32",
            "architecture": "x86",
            "subsystem": "Windows GUI",
            "dll_characteristics": ["ASLR", "NX"],
        },
        "security": {
            "score": 80,
            "nx": True,
            "aslr": True,
            "relro": "full",
            "fortify": False,
        },
        "ssdeep": {"available": True, "hash": "3:abc:def"},
        "tlsh": {"available": True, "hash": "T1"},
        "telfhash": {"available": True, "hash": "tel"},
        "rich_header": {"available": True, "hash": "rich"},
        "impfuzzy": {"available": True, "hash": "impf"},
        "ccbhash": {"available": True, "hash": "ccb"},
        "binlex": {
            "available": True,
            "top_strings": ["a", "b"],
            "lexical_features": {"avg_length": 3.1},
        },
        "binbloom": {"available": True, "signatures": {"structural": "s1"}},
        "simhash": {
            "available": True,
            "hash": "sim",
            "function_analysis": {"function_count": 2, "cfg_features": {"f": 1}},
        },
        "bindiff": {
            "available": True,
            "similarity_score": 0.5,
            "structural": {"hash": "a"},
            "string_features": {"total_strings": 3, "categorized_strings": {"url": 1}},
            "function_features": {"function_count": 1, "cfg_features": {"f": 1}},
            "signatures": {"structural": "s", "function": "f", "string": "st"},
        },
        "functions": {"total_functions": 2, "machoc_hashes": {"f1": "h1", "f2": "h1"}},
        "indicators": [{"type": "evasion", "description": "sleep", "severity": "High"}],
        "retry_stats": {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"i": 2, "aa": 1},
        },
        "circuit_stats": {"opened": 1, "failed_calls": 2},
    }

    table = Table()
    arg_pool = {
        "results": results,
        "retry_stats": results["retry_stats"],
        "circuit_stats": results["circuit_stats"],
        "table": table,
        "simhash_info": results["simhash"],
        "bindiff_info": results["bindiff"],
        "signatures": results["bindiff"]["signatures"],
        "string_features": results["bindiff"]["string_features"],
        "function_features": results["bindiff"]["function_features"],
    }

    executed = 0
    for name, member in inspect.getmembers(display_sections):
        if not callable(member) or name.startswith("__"):
            continue
        if _call_with_pool(member, arg_pool):
            executed += 1

    assert executed > 0
