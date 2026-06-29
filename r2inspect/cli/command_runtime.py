#!/usr/bin/env python3
"""Shared runtime helpers for CLI commands."""

from __future__ import annotations

from typing import Any


def configure_logging_levels(verbose: bool, quiet: bool) -> None:
    import logging
    import warnings

    if quiet:
        warnings.filterwarnings("ignore")
        logging.getLogger("r2pipe").setLevel(logging.CRITICAL)
        logging.getLogger("r2inspect").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.modules").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.pipeline").setLevel(logging.WARNING)
        return
    level = logging.INFO if verbose else logging.WARNING
    logging.getLogger("r2inspect").setLevel(level)
    logging.getLogger("r2inspect.modules").setLevel(level)
    logging.getLogger("r2inspect.pipeline").setLevel(level)


def configure_quiet_logging(quiet: bool) -> None:
    import logging

    if not quiet:
        return
    logging.getLogger("r2pipe").setLevel(logging.CRITICAL)
    logging.getLogger("r2inspect").setLevel(logging.WARNING)
    logging.getLogger("r2inspect.modules").setLevel(logging.WARNING)
    logging.getLogger("r2inspect.pipeline").setLevel(logging.WARNING)


def apply_thread_settings(config: Any, threads: int | None) -> None:
    if threads is None:
        return
    thread_count = int(threads)
    if thread_count < 1 or thread_count > 50:
        raise ValueError("threads must be between 1 and 50")
    config.apply_overrides(
        {
            "pipeline": {
                "max_workers": thread_count,
                "parallel_execution": bool(thread_count > 1),
            }
        }
    )


def build_analysis_options(yara: str | None = None, xor: str | None = None) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if yara:
        # The YARA stage reads "custom_yara"; the old "yara_rules_dir" key was
        # never consumed, so --yara was silently ignored for single-file scans.
        options["custom_yara"] = yara
    if xor:
        options["xor_search"] = xor
    return options
