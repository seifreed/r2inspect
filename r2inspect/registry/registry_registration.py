"""Shared analyzer registry helpers for registration workflows."""

from __future__ import annotations

import logging
from typing import Any, cast

from .categories import AnalyzerCategory
from .metadata import AnalyzerMetadata
from .metadata_extraction import auto_extract_metadata

_logger = logging.getLogger(__name__)


class AnalyzerRegistryRegistrationMixin:
    """Registration helpers shared by the analyzer registry."""

    _analyzers: dict[str, AnalyzerMetadata]
    _lazy_loading: bool
    _lazy_loader: Any
    is_base_analyzer: Any  # provided by AnalyzerRegistryBaseMixin
    _parse_category: Any  # provided by AnalyzerRegistryBaseMixin

    def register_from_instance(
        self,
        analyzer_instance: Any,
        name: str | None = None,
        required: bool = False,
        dependencies: set[str] | None = None,
        override_category: AnalyzerCategory | None = None,
        override_formats: set[str] | None = None,
        override_description: str | None = None,
    ) -> None:
        if not self.is_base_analyzer(type(analyzer_instance)):
            raise ValueError(f"{type(analyzer_instance).__name__} is not a BaseAnalyzer subclass")

        extracted_name = name or analyzer_instance.get_name()
        category_str = override_category or analyzer_instance.get_category()
        formats = (
            override_formats
            if override_formats is not None
            else analyzer_instance.get_supported_formats()
        )
        description = override_description or analyzer_instance.get_description()
        category_enum = self._parse_category(category_str)

        self._analyzers[extracted_name] = self._build_metadata(
            name=extracted_name,
            analyzer_class=type(analyzer_instance),
            category=category_enum,
            file_formats=formats,
            required=required,
            dependencies=dependencies,
            description=description,
        )

    def register(
        self,
        name: str,
        analyzer_class: type | None = None,
        category: AnalyzerCategory | str | None = None,
        file_formats: set[str] | None = None,
        required: bool = False,
        dependencies: set[str] | None = None,
        description: str = "",
        auto_extract: bool = True,
        module_path: str | None = None,
        class_name: str | None = None,
    ) -> None:
        self._validate_registration_name(name)

        is_lazy, _ = self._resolve_registration_mode(analyzer_class, module_path, class_name)
        if is_lazy:
            lazy_result = self._handle_lazy_registration(
                name=name,
                module_path=module_path,
                class_name=class_name,
                category=category,
                file_formats=file_formats,
                required=required,
                dependencies=dependencies,
                description=description,
            )
            if lazy_result is not None:
                return
            analyzer_class = self._lazy_fallback_analyzer_class(module_path, class_name)
            auto_extract = False

        analyzer_class = self._ensure_analyzer_class(analyzer_class)
        category, file_formats, description = self._auto_extract_metadata(
            analyzer_class=analyzer_class,
            name=name,
            category=category,
            file_formats=file_formats,
            description=description,
            auto_extract=auto_extract,
        )
        category = self._ensure_category(analyzer_class, category)

        if name in self._analyzers:
            _logger.warning(
                "Overwriting analyzer registration '%s': %s -> %s",
                name,
                self._analyzers[name].analyzer_class.__name__,
                analyzer_class.__name__,
            )
        self._analyzers[name] = self._build_metadata(
            name=name,
            analyzer_class=analyzer_class,
            category=category,
            file_formats=file_formats,
            required=required,
            dependencies=dependencies,
            description=description,
        )

    def _validate_registration_name(self, name: str) -> None:
        if not name:
            raise ValueError("Analyzer name cannot be empty")

    def _build_metadata(
        self,
        *,
        name: str,
        analyzer_class: type,
        category: AnalyzerCategory,
        file_formats: set[str] | None,
        required: bool,
        dependencies: set[str] | None,
        description: str,
    ) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name=name,
            analyzer_class=analyzer_class,
            category=category,
            file_formats=file_formats,
            required=required,
            dependencies=dependencies,
            description=description,
        )

    def _resolve_registration_mode(
        self,
        analyzer_class: type | None,
        module_path: str | None,
        class_name: str | None,
    ) -> tuple[bool, bool]:
        is_lazy = module_path is not None and class_name is not None
        is_eager = analyzer_class is not None
        if not is_lazy and not is_eager:
            raise ValueError(
                "Must provide either analyzer_class (eager) or module_path+class_name (lazy)"
            )
        if is_lazy and is_eager:
            raise ValueError(
                "Cannot provide both analyzer_class and module_path+class_name. "
                "Choose eager or lazy registration."
            )
        return is_lazy, is_eager

    def _handle_lazy_registration(
        self,
        name: str,
        module_path: str | None,
        class_name: str | None,
        category: AnalyzerCategory | str | None,
        file_formats: set[str] | None,
        required: bool,
        dependencies: set[str] | None,
        description: str,
    ) -> AnalyzerMetadata | None:
        if module_path is None or class_name is None:
            raise ValueError("module_path and class_name are required for lazy registration")
        if category is None:
            raise ValueError(f"Category is required for lazy registration of analyzer '{name}'")

        resolved_category = (
            category if isinstance(category, AnalyzerCategory) else self._parse_category(category)
        )

        if self._lazy_loading and self._lazy_loader is not None:
            lazy_module_path: str = module_path
            lazy_class_name: str = class_name
            self._lazy_loader.register(
                name=name,
                module_path=lazy_module_path,
                class_name=lazy_class_name,
                category=resolved_category.value,
                formats=file_formats,
                metadata={
                    "required": required,
                    "dependencies": dependencies or set(),
                    "description": description,
                },
            )

            class LazyPlaceholder:
                __name__ = lazy_class_name
                __module__ = lazy_module_path

            metadata = AnalyzerMetadata(
                name=name,
                analyzer_class=LazyPlaceholder,
                category=resolved_category,
                file_formats=file_formats,
                required=required,
                dependencies=dependencies,
                description=description,
            )

            self._analyzers[name] = metadata
            return metadata
        return None

    def _lazy_fallback_analyzer_class(
        self, module_path: str | None, class_name: str | None
    ) -> type:
        if module_path is None or class_name is None:
            raise ValueError("module_path and class_name are required for lazy fallback")
        import importlib

        module = importlib.import_module(module_path)
        return cast(type[Any], getattr(module, class_name))

    def _ensure_analyzer_class(self, analyzer_class: type | None) -> type:
        if analyzer_class is None:
            raise ValueError("analyzer_class is required for eager registration")
        return analyzer_class

    def _auto_extract_metadata(
        self,
        analyzer_class: type,
        name: str,
        category: AnalyzerCategory | str | None,
        file_formats: set[str] | None,
        description: str,
        auto_extract: bool,
    ) -> tuple[AnalyzerCategory | str | None, set[str] | None, str]:
        return auto_extract_metadata(
            analyzer_class,
            name=name,
            category=category,
            file_formats=file_formats,
            description=description,
            auto_extract=auto_extract,
            is_base_analyzer=self.is_base_analyzer,
        )

    def _ensure_category(
        self, analyzer_class: type, category: AnalyzerCategory | str | None
    ) -> AnalyzerCategory:
        if category is None:
            raise ValueError(
                f"Category must be provided for {analyzer_class.__name__}. "
                "Either specify category parameter or ensure analyzer inherits from "
                "BaseAnalyzer with get_category() implemented."
            )
        if not isinstance(category, AnalyzerCategory):
            return cast(AnalyzerCategory, self._parse_category(category))
        return category

    def unregister(self, name: str) -> bool:
        if name in self._analyzers:
            del self._analyzers[name]
            return True
        return False

    def is_registered(self, name: str) -> bool:
        return name in self._analyzers
