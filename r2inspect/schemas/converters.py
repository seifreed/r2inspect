#!/usr/bin/env python3
"""Converters between dict results and schema models."""

from typing import Any, TypeVar

from pydantic import BaseModel

from .converter_runtime import (
    ResultConverterImpl,
    dict_to_model_impl,
    model_to_dict_impl,
    safe_convert_impl,
    validate_result_impl,
)

TModel = TypeVar("TModel", bound=BaseModel)


def dict_to_model(data: dict[str, Any], model_class: type[TModel], strict: bool = False) -> TModel:
    return dict_to_model_impl(data, model_class, strict=strict)


def model_to_dict(
    model: BaseModel,
    by_alias: bool = False,
    exclude_none: bool = True,
) -> dict[str, Any]:
    return model_to_dict_impl(model, by_alias=by_alias, exclude_none=exclude_none)


class ResultConverter(ResultConverterImpl):
    pass


def safe_convert(
    data: Any, model_class: type[TModel], default: TModel | None = None
) -> TModel | None:
    return safe_convert_impl(data, model_class, default=default)


def validate_result(result: BaseModel) -> bool:
    return validate_result_impl(result)
