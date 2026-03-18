#!/usr/bin/env python3
"""R2Pipe adapter query methods."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, TypeVar, cast

from ..interfaces import R2CommandInterface
from ..infrastructure.logging import get_logger
from ..infrastructure.r2_helpers import safe_cmd, safe_cmd_dict, safe_cmdj
from .r2pipe_query_bytes import R2PipeByteQueryMixin
from .r2pipe_query_cached import R2PipeCachedQueryMixin
from .r2pipe_query_text import R2PipeTextQueryMixin
from .validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)

logger = get_logger(__name__)

T = TypeVar("T")


class R2PipeQueryMixin(
    R2PipeCachedQueryMixin, R2PipeTextQueryMixin, R2PipeByteQueryMixin, R2CommandInterface
):
    """Query helpers for r2pipe-backed adapters."""

    _cache: dict[str, Any]

    def _cached_query(
        self,
        cmd: str,
        data_type: Literal["list", "dict"] = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        raise NotImplementedError

    def _maybe_force_error(self, method: str) -> None:
        raise NotImplementedError

    def _safe_query(self, action: Callable[[], T], default: T, error_message: str) -> T:
        try:
            return action()
        except Exception as e:
            logger.error("%s: %s", error_message, e)
            return default

    def _safe_cached_query(
        self,
        cmd: str,
        data_type: Literal["list", "dict"],
        default: list | dict,
        *,
        error_msg: str = "",
        cache: bool = True,
        error_label: str,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        return cast(
            list[dict[str, Any]] | dict[str, Any],
            self._safe_query(
                lambda: self._cached_query(
                    cmd, data_type, default=default, error_msg=error_msg, cache=cache
                ),
                default,
                f"Error retrieving {error_label}",
            ),
        )
