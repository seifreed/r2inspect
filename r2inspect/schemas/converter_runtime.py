#!/usr/bin/env python3
"""Runtime helpers for schema conversion."""

import logging
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .base import AnalysisResultBase

logger = logging.getLogger(__name__)
TModel = TypeVar("TModel", bound=BaseModel)


def dict_to_model_impl(
    data: dict[str, Any], model_class: type[TModel], strict: bool = False
) -> TModel:
    try:
        return model_class(**data)
    except ValidationError as exc:
        if strict:
            raise
        # Log the validation failure but still validate with lenient mode
        # instead of bypassing all validation with model_construct()
        logger.warning(
            "Validation error converting to %s: %s. Attempting lenient construction.",
            model_class.__name__,
            exc,
        )
        # Filter data to only include fields defined on the model
        model_fields = set(model_class.model_fields.keys())
        dropped = {k for k in data if k not in model_fields}
        if dropped:
            logger.debug("Dropped unknown fields for %s: %s", model_class.__name__, dropped)
        filtered = {k: v for k, v in data.items() if k in model_fields}
        try:
            return model_class.model_validate(filtered)
        except ValidationError as inner_exc:
            # Build instance with only the fields that individually validate,
            # coercing invalid ones to their defaults.
            logger.warning(
                "Lenient construction for %s failed: %s. Using field defaults for bad values.",
                model_class.__name__,
                inner_exc,
            )
            # Identify which fields caused the validation error and exclude them.
            # Use the error details from Pydantic to pinpoint bad fields.
            bad_fields: set[str] = set()
            for error in inner_exc.errors():
                loc = error.get("loc", ())
                if loc:
                    bad_fields.add(str(loc[0]))
            safe_fields = {k: v for k, v in filtered.items() if k not in bad_fields}
            if bad_fields:
                logger.debug("Excluded invalid fields for %s: %s", model_class.__name__, bad_fields)
            try:
                return model_class.model_validate(safe_fields)
            except ValidationError:
                # All remaining fields with defaults only
                return model_class.model_validate({})


def model_to_dict_impl(
    model: BaseModel,
    by_alias: bool = False,
    exclude_none: bool = True,
) -> dict[str, Any]:
    return model.model_dump(exclude_none=exclude_none, by_alias=by_alias)


class ResultConverterImpl:
    _schema_registry: dict[str, type[BaseModel]] = {}
    _default_schema: type[BaseModel] = AnalysisResultBase

    @classmethod
    def register_schema(cls, analyzer_name: str, schema_class: type[BaseModel]) -> None:
        normalized_name = analyzer_name.lower().strip()
        cls._schema_registry[normalized_name] = schema_class
        logger.debug(
            "Registered schema %s for analyzer '%s'", schema_class.__name__, normalized_name
        )

    @classmethod
    def register_schemas(cls, schemas: dict[str, type[BaseModel]]) -> None:
        for name, schema in schemas.items():
            cls.register_schema(name, schema)

    @classmethod
    def get_schema(cls, analyzer_name: str) -> type[BaseModel]:
        normalized_name = analyzer_name.lower().strip()
        return cls._schema_registry.get(normalized_name, cls._default_schema)

    @classmethod
    def convert_result(
        cls, analyzer_name: str, result: dict[str, Any], strict: bool = False
    ) -> BaseModel:
        schema_class = cls.get_schema(analyzer_name)
        if "analyzer_name" not in result:
            result = result.copy()
            result["analyzer_name"] = analyzer_name
        return dict_to_model_impl(result, schema_class, strict=strict)

    @classmethod
    def convert_results(
        cls, results: dict[str, dict[str, Any]], strict: bool = False
    ) -> dict[str, BaseModel | dict[str, Any]]:
        converted: dict[str, BaseModel | dict[str, Any]] = {}
        for analyzer_name, result in results.items():
            try:
                converted[analyzer_name] = cls.convert_result(analyzer_name, result, strict=strict)
            except Exception as exc:
                logger.error("Failed to convert result for analyzer '%s': %s", analyzer_name, exc)
                if not strict:
                    converted[analyzer_name] = result
        return converted

    @classmethod
    def list_registered_schemas(cls) -> dict[str, str]:
        return {name: schema.__name__ for name, schema in cls._schema_registry.items()}


def safe_convert_impl(
    data: Any, model_class: type[TModel], default: TModel | None = None
) -> TModel | None:
    if data is None:
        return default
    if isinstance(data, model_class):
        return data
    try:
        if isinstance(data, dict):
            return dict_to_model_impl(data, model_class, strict=False)
        logger.warning("Cannot convert %s to %s", type(data), model_class.__name__)
        return default
    except Exception as exc:
        logger.error("Conversion failed: %s", exc)
        return default


def validate_result_impl(result: BaseModel) -> bool:
    try:
        data = model_to_dict_impl(result)
        result.__class__(**data)
        return True
    except ValidationError as exc:
        logger.error("Validation failed: %s", exc)
        return False
