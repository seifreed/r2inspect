#!/usr/bin/env python3
"""Initialization helpers for pipeline builder runtime dependencies."""

from __future__ import annotations

from typing import Any


def apply_runtime_dependencies(builder: Any, deps: Any) -> None:
    builder.analyzer_factory = deps.analyzer_factory
    builder.hash_calculator = deps.hash_calculator
    builder.file_type_detector = deps.file_type_detector
    builder.result_aggregator_factory = deps.result_aggregator_factory
