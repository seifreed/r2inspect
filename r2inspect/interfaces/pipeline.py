#!/usr/bin/env python3
"""Pipeline-facing protocols for dependency inversion."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class AnalyzerMetadataLike(Protocol):
    """Minimal analyzer metadata required by pipeline stages."""

    def supports_format(self, file_format: str) -> bool: ...


class AnalyzerRegistryLike(Protocol):
    """Resolver for analyzer classes and metadata."""

    def get_analyzer_class(self, name: str) -> type[Any] | None: ...

    def get_by_category(self, category: Any) -> dict[str, type[Any]]: ...

    def get_metadata(self, name: str) -> AnalyzerMetadataLike | None: ...


class AnalyzerFactoryLike(Protocol):
    """Build analyzers from runtime dependencies."""

    def __call__(
        self,
        analyzer_class: type[Any],
        *,
        adapter: Any | None = None,
        r2: Any | None = None,
        config: Any | None = None,
        filename: str | None = None,
    ) -> Any: ...


class HashCalculatorLike(Protocol):
    """Calculate hashes for a file path."""

    def __call__(self, file_path: str, /) -> dict[str, str]: ...


class FileTypeDetectorLike(Protocol):
    """Detect file type information for a file path."""

    def __call__(self, file_path: str, /) -> dict[str, Any]: ...


class ResultAggregatorFactoryLike(Protocol):
    """Build aggregators used by pipeline terminal stages."""

    def __call__(self) -> Any: ...


StageProgressCallback = Callable[[str, int, int], None]
