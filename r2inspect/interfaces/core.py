#!/usr/bin/env python3
"""Core protocol interfaces for dependency inversion."""

from typing import Any, Protocol

from .binary_analyzer import BinaryAnalyzerInterface


class ConfigLike(Protocol):
    @property
    def typed_config(self) -> Any: ...


class FileValidatorLike(Protocol):
    def validate(self) -> bool: ...

    def _file_size_mb(self) -> float: ...


class ResultAggregatorLike(Protocol):
    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]: ...

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]: ...


class MemoryMonitorLike(Protocol):
    def check_memory(self, force: bool = False) -> dict[str, Any]: ...

    def is_memory_available(self, required_mb: float) -> bool: ...

    def _trigger_gc(self, aggressive: bool = False) -> None: ...


class R2CommandInterface(Protocol):
    def cmd(self, command: str) -> str: ...

    def cmdj(self, command: str) -> Any: ...


class AnalyzerBackend(BinaryAnalyzerInterface, Protocol):
    """Backend interface used by analyzers."""
