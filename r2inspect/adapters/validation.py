#!/usr/bin/env python3
"""Facade for r2pipe response validation and sanitization."""

from typing import Any

from .validation_primitives import (
    clean_dict_values as _clean_dict_values_impl,
    clean_list_items as _clean_list_items_impl,
    is_valid_response as _is_valid_response,
    sanitize_output as _sanitize_output,
    validate_address as _validate_address_impl,
    validate_bytes_data as _validate_bytes_data_impl,
    validate_dict_data as _validate_dict_data_impl,
    validate_list_data as _validate_list_data_impl,
    validate_size as _validate_size_impl,
    validate_str_data as _validate_str_data_impl,
)
from ..infrastructure.logging import get_logger

logger = get_logger(__name__)


def validate_r2_data(
    data: Any, expected_type: str = "dict"
) -> dict[str, Any] | list[dict[str, Any]] | Any:
    if expected_type == "dict":
        return _validate_dict_data(data)
    if expected_type == "list":
        return _validate_list_data(data)
    if expected_type == "str":
        return _validate_str_data(data)
    if expected_type == "bytes":
        return _validate_bytes_data(data)
    if expected_type == "any":
        return data
    logger.warning("Unknown expected_type '%s', returning data as-is", expected_type)
    return data


def _validate_dict_data(data: Any) -> dict[str, Any]:
    return _validate_dict_data_impl(data, logger)


def _validate_list_data(data: Any) -> list[dict[str, Any]]:
    return _validate_list_data_impl(data, logger)


def _validate_str_data(data: Any) -> str:
    return _validate_str_data_impl(data, logger)


def _validate_bytes_data(data: Any) -> bytes:
    return _validate_bytes_data_impl(data, logger)


def _clean_list_items(data: list[Any]) -> list[dict[str, Any]]:
    return _clean_list_items_impl(data, logger)


def _clean_dict_values(data: dict[str, Any]) -> None:
    _clean_dict_values_impl(data)


def sanitize_r2_output(output: str) -> str:
    return _sanitize_output(output)


def is_valid_r2_response(response: Any) -> bool:
    return _is_valid_response(response)


def validate_address(address: Any) -> int:
    return _validate_address_impl(address)


def validate_size(size: Any) -> int:
    return _validate_size_impl(size)
