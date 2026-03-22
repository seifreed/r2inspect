#!/usr/bin/env python3
"""Helper functions shared by BaseAnalyzer."""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def normalize_filepath(filepath: Any | None) -> Path | None:
    if not filepath:
        return None
    return filepath if isinstance(filepath, Path) else Path(filepath)


def derive_analyzer_name(instance: Any) -> str:
    class_name = instance.__class__.__name__
    if class_name.endswith(("Analyzer", "Detector")):
        class_name = class_name[:-8]
    return re.sub(r"(?<!^)(?=[A-Z])", "_", class_name).lower()


def log_with_root(logger: Any, level: str, analyzer_name: str, message: str) -> None:
    payload = f"[{analyzer_name}] {message}"
    getattr(logger, level)(payload)
    getattr(logging.getLogger(), level)(payload)


def measure_execution_time(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        if isinstance(result, dict):
            result["execution_time"] = elapsed
        return result

    return wrapper


@contextmanager
def analysis_context(
    log_error: Callable[[str], None],
    result: dict[str, Any],
    *,
    error_message: str,
    set_available: bool = True,
) -> Iterator[None]:
    try:
        yield
        if set_available:
            result["available"] = True
    except Exception as exc:
        result["error"] = str(exc)
        log_error(f"{error_message}: {exc}")


def analyzer_str(instance: Any) -> str:
    filename = instance.filepath.name if instance.filepath else "no_file"
    return (
        f"{instance.__class__.__name__}("
        f"name={instance.get_name()}, "
        f"category={instance.get_category()}, "
        f"file={filename})"
    )


def analyzer_repr(instance: Any) -> str:
    return (
        f"{instance.__class__.__name__}("
        f"filepath={instance.filepath!r}, "
        f"adapter={'<adapter>' if instance.adapter else None}, "
        f"config={'<Config>' if instance.config else None})"
    )
