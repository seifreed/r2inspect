#!/usr/bin/env python3
"""
Converters Between Dict and Pydantic Models

Utilities to convert between traditional dict results and type-safe Pydantic models,
ensuring backward compatibility and seamless migration.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

import logging
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .base import AnalysisResultBase

logger = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)


def dict_to_model(data: dict[str, Any], model_class: type[TModel], strict: bool = False) -> TModel:
    """
    Convert dictionary to Pydantic model.

    This function provides safe conversion with error handling:
    - In strict mode: Raises ValidationError on validation failure
    - In non-strict mode: Logs warning and constructs model with raw data

    Args:
        data: Dictionary data to convert
        model_class: Target Pydantic model class
        strict: If True, raise on validation error. If False, log and use raw data.

    Returns:
        Pydantic model instance

    Raises:
        ValidationError: If strict=True and validation fails

    Example:
        >>> from r2inspect.schemas.hashing import HashAnalysisResult
        >>> data = {"available": True, "hash_type": "ssdeep", "hash_value": "abc"}
        >>> result = dict_to_model(data, HashAnalysisResult)
        >>> print(result.hash_type)
        'ssdeep'
    """
    try:
        return model_class(**data)
    except ValidationError as e:
        if strict:
            raise
        logger.warning(
            f"Validation error converting to {model_class.__name__}: {e}. "
            f"Using construct() to preserve data."
        )
        # Use construct to bypass validation but preserve data
        return model_class.model_construct(**data)


def model_to_dict(
    model: BaseModel,
    include_none: bool = False,
    by_alias: bool = False,
    exclude_none: bool = True,
) -> dict[str, Any]:
    """
    Convert Pydantic model to dictionary.

    Args:
        model: Pydantic model instance
        include_none: Include fields with None values (deprecated, use exclude_none)
        by_alias: Use field aliases instead of field names
        exclude_none: Exclude fields with None values (recommended)

    Returns:
        Dictionary representation

    Example:
        >>> result = HashAnalysisResult(
        ...     available=True,
        ...     hash_type="ssdeep",
        ...     hash_value="abc123"
        ... )
        >>> data = model_to_dict(result)
        >>> print(data["hash_type"])
        'ssdeep'
    """
    # Handle deprecated include_none parameter
    if include_none:
        exclude_none = False

    return model.model_dump(exclude_none=exclude_none, by_alias=by_alias)


class ResultConverter:
    """
    Central converter registry for analyzer results.

    This class maintains a registry of analyzer names to their corresponding
    Pydantic schema classes, enabling automatic conversion based on analyzer type.

    Usage:
        # Register schemas (usually done in __init__.py)
        ResultConverter.register_schema("ssdeep", HashAnalysisResult)

        # Convert result
        result = ResultConverter.convert_result("ssdeep", data_dict)
    """

    # Registry mapping analyzer name -> schema class
    _schema_registry: dict[str, type[BaseModel]] = {}

    # Default schema for unknown analyzers
    _default_schema: type[BaseModel] = AnalysisResultBase

    @classmethod
    def register_schema(cls, analyzer_name: str, schema_class: type[BaseModel]) -> None:
        """
        Register a schema for an analyzer.

        Args:
            analyzer_name: Name of the analyzer (lowercase)
            schema_class: Pydantic model class for this analyzer

        Example:
            >>> ResultConverter.register_schema("ssdeep", HashAnalysisResult)
        """
        normalized_name = analyzer_name.lower().strip()
        cls._schema_registry[normalized_name] = schema_class
        logger.debug(f"Registered schema {schema_class.__name__} for analyzer '{normalized_name}'")

    @classmethod
    def register_schemas(cls, schemas: dict[str, type[BaseModel]]) -> None:
        """
        Register multiple schemas at once.

        Args:
            schemas: Dictionary mapping analyzer names to schema classes

        Example:
            >>> ResultConverter.register_schemas({
            ...     "ssdeep": HashAnalysisResult,
            ...     "tlsh": HashAnalysisResult,
            ...     "pe": FormatAnalysisResult
            ... })
        """
        for name, schema in schemas.items():
            cls.register_schema(name, schema)

    @classmethod
    def get_schema(cls, analyzer_name: str) -> type[BaseModel]:
        """
        Get the schema class for an analyzer.

        Args:
            analyzer_name: Name of the analyzer

        Returns:
            Schema class (or default if not registered)

        Example:
            >>> schema = ResultConverter.get_schema("ssdeep")
            >>> print(schema.__name__)
            'HashAnalysisResult'
        """
        normalized_name = analyzer_name.lower().strip()
        return cls._schema_registry.get(normalized_name, cls._default_schema)

    @classmethod
    def convert_result(
        cls, analyzer_name: str, result: dict[str, Any], strict: bool = False
    ) -> BaseModel:
        """
        Convert analyzer result dict to appropriate Pydantic model.

        This is the main conversion method that automatically selects
        the correct schema based on analyzer name.

        Args:
            analyzer_name: Name of the analyzer
            result: Result dictionary from analyzer
            strict: If True, raise on validation error

        Returns:
            Pydantic model instance

        Example:
            >>> data = {
            ...     "available": True,
            ...     "hash_type": "ssdeep",
            ...     "hash_value": "3:abc:def"
            ... }
            >>> result = ResultConverter.convert_result("ssdeep", data)
            >>> print(type(result).__name__)
            'HashAnalysisResult'
        """
        schema_class = cls.get_schema(analyzer_name)

        # Ensure analyzer_name is in result
        if "analyzer_name" not in result:
            result = result.copy()
            result["analyzer_name"] = analyzer_name

        return dict_to_model(result, schema_class, strict=strict)

    @classmethod
    def convert_results(
        cls, results: dict[str, dict[str, Any]], strict: bool = False
    ) -> dict[str, BaseModel | dict[str, Any]]:
        """
        Convert multiple analyzer results.

        Args:
            results: Dictionary mapping analyzer names to result dicts
            strict: If True, raise on validation error

        Returns:
            Dictionary mapping analyzer names to Pydantic models

        Example:
            >>> results_dict = {
            ...     "ssdeep": {"available": True, "hash_type": "ssdeep", ...},
            ...     "pe": {"available": True, "format": "PE32", ...}
            ... }
            >>> converted = ResultConverter.convert_results(results_dict)
            >>> print(type(converted["ssdeep"]).__name__)
            'HashAnalysisResult'
        """
        converted: dict[str, BaseModel | dict[str, Any]] = {}
        for analyzer_name, result in results.items():
            try:
                converted[analyzer_name] = cls.convert_result(analyzer_name, result, strict=strict)
            except Exception as e:
                logger.error(f"Failed to convert result for analyzer '{analyzer_name}': {e}")
                # Store as-is if conversion fails
                if not strict:
                    converted[analyzer_name] = result

        return converted

    @classmethod
    def list_registered_schemas(cls) -> dict[str, str]:
        """
        Get list of all registered schemas.

        Returns:
            Dictionary mapping analyzer names to schema class names

        Example:
            >>> schemas = ResultConverter.list_registered_schemas()
            >>> print(schemas)
            {'ssdeep': 'HashAnalysisResult', 'pe': 'FormatAnalysisResult', ...}
        """
        return {name: schema.__name__ for name, schema in cls._schema_registry.items()}


def safe_convert(
    data: Any, model_class: type[TModel], default: TModel | None = None
) -> TModel | None:
    """
    Safely convert data to model, returning default on failure.

    This is a convenience function for optional conversions where
    you want to handle failures gracefully.

    Args:
        data: Data to convert (dict or model)
        model_class: Target model class
        default: Default value to return on failure

    Returns:
        Model instance or default value

    Example:
        >>> data = {"available": True, "hash_type": "invalid"}
        >>> result = safe_convert(data, HashAnalysisResult)
        >>> print(result)  # Will be None due to validation error
        None
    """
    if data is None:
        return default

    # Already correct type
    if isinstance(data, model_class):
        return data

    # Try conversion
    try:
        if isinstance(data, dict):
            return dict_to_model(data, model_class, strict=False)
        else:
            logger.warning(f"Cannot convert {type(data)} to {model_class.__name__}")
            return default
    except Exception as e:
        logger.error(f"Conversion failed: {e}")
        return default


def validate_result(result: BaseModel) -> bool:
    """
    Validate a Pydantic model instance.

    Args:
        result: Pydantic model instance to validate

    Returns:
        True if valid, False otherwise

    Example:
        >>> result = HashAnalysisResult(
        ...     available=True,
        ...     hash_type="ssdeep",
        ...     hash_value="abc"
        ... )
        >>> print(validate_result(result))
        True
    """
    try:
        # Re-validate by converting to dict and back
        data = model_to_dict(result)
        result.__class__(**data)
        return True
    except ValidationError as e:
        logger.error(f"Validation failed: {e}")
        return False
