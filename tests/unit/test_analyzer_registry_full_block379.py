from __future__ import annotations

import sys
from pathlib import Path

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import (
    AnalyzerCategory,
    AnalyzerMetadata,
    AnalyzerRegistry,
)


class DummyAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return {"available": True}

    def get_category(self) -> str:
        return "metadata"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "dummy"


class BadAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, object]:
        return {}

    def get_category(self) -> str:
        raise RuntimeError("bad category")


class NoAnalyze(BaseAnalyzer):
    pass


def test_analyzer_metadata_validations() -> None:
    meta = AnalyzerMetadata(
        name="x",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        dependencies={"dep"},
    )
    assert meta.supports_format("pe") is True
    assert meta.supports_format("elf") is False
    assert meta.to_dict()["name"] == "x"

    with pytest.raises(ValueError):
        AnalyzerMetadata(
            name="",
            analyzer_class=DummyAnalyzer,
            category=AnalyzerCategory.METADATA,
        )

    with pytest.raises(ValueError):
        AnalyzerMetadata(
            name="x",
            analyzer_class=None,  # type: ignore[arg-type]
            category=AnalyzerCategory.METADATA,
        )

    with pytest.raises(TypeError):
        AnalyzerMetadata(
            name="x",
            analyzer_class=DummyAnalyzer,
            category="bad",  # type: ignore[arg-type]
        )


def test_registry_validation_and_registration(tmp_path: Path) -> None:
    registry = AnalyzerRegistry(lazy_loading=False)

    assert registry.validate_analyzer(DummyAnalyzer) == (True, None)
    assert registry.validate_analyzer(DummyAnalyzer()) == (
        False,
        "analyzer_class must be a class, not an instance",
    )
    valid, message = registry.validate_analyzer(NoAnalyze)
    assert valid is False
    assert message == "analyze() method is not implemented (still abstract)"

    with pytest.raises(ValueError):
        registry.register(name="")

    with pytest.raises(ValueError):
        registry._resolve_registration_mode(None, None, None)

    with pytest.raises(ValueError):
        registry._resolve_registration_mode(DummyAnalyzer, "mod", "cls")

    registry.register(
        name="dummy",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        required=True,
        description="dummy",
    )
    assert registry.is_registered("dummy") is True
    assert registry.get_metadata("dummy") is not None
    assert registry.get_analyzer_class("dummy") is DummyAnalyzer

    assert registry.get_analyzers_for_format("PE")["dummy"] is DummyAnalyzer
    assert registry.get_required_analyzers()["dummy"] is DummyAnalyzer
    assert "dummy" not in registry.get_optional_analyzers()

    assert "dummy" in registry
    assert len(registry) == 1
    assert list(iter(registry)) == ["dummy"]

    assert registry.unregister("dummy") is True
    assert registry.unregister("dummy") is False

    # Lazy fallback when lazy loading disabled
    module_path = "dummy_mod"
    module_file = tmp_path / f"{module_path}.py"
    module_file.write_text(
        "class DummyLazy:\n" "    def __init__(self, *args, **kwargs):\n" "        pass\n"
    )
    sys.path.insert(0, str(tmp_path))
    try:
        registry.register(
            name="lazy",
            module_path=module_path,
            class_name="DummyLazy",
            category=AnalyzerCategory.METADATA,
        )
        cls = registry.get_analyzer_class("lazy")
        assert cls is not None
        assert cls.__name__ == "DummyLazy"
    finally:
        sys.path.remove(str(tmp_path))


def test_registry_lazy_loading_and_entry_points(tmp_path: Path) -> None:
    registry = AnalyzerRegistry(lazy_loading=True)

    module_path = "lazy_mod"
    module_file = tmp_path / f"{module_path}.py"
    module_file.write_text(
        "class LazyAnalyzer:\n" "    def __init__(self, *args, **kwargs):\n" "        pass\n"
    )
    sys.path.insert(0, str(tmp_path))
    try:
        registry.register(
            name="lazy",
            module_path=module_path,
            class_name="LazyAnalyzer",
            category=AnalyzerCategory.METADATA,
        )
        assert registry.get_analyzer_class("lazy").__name__ == "LazyAnalyzer"
    finally:
        sys.path.remove(str(tmp_path))

    with pytest.raises(ValueError):
        registry._handle_lazy_registration(
            name="x",
            module_path=None,
            class_name=None,
            category=AnalyzerCategory.METADATA,
            file_formats=None,
            required=False,
            dependencies=None,
            description="",
        )

    with pytest.raises(ValueError):
        registry._parse_category("unknown")

    with pytest.raises(TypeError):
        registry._parse_category(123)

    # Entry point handling
    class _EntryPoint:
        def __init__(self, name: str, obj: object | None = None, raise_load: bool = False):
            self.name = name
            self._obj = obj
            self._raise = raise_load

        def load(self) -> object:
            if self._raise:
                raise RuntimeError("load error")
            return self._obj  # type: ignore[return-value]

    loaded = registry._handle_entry_point(_EntryPoint("fail", raise_load=True))
    assert loaded == 0

    def _callable(reg: AnalyzerRegistry) -> None:
        reg.register(
            name="callable",
            analyzer_class=DummyAnalyzer,
            category=AnalyzerCategory.METADATA,
        )

    loaded = registry._handle_entry_point(_EntryPoint("callable", _callable))
    assert loaded == 1

    loaded = registry._handle_entry_point(_EntryPoint("class", DummyAnalyzer))
    assert loaded == 1

    assert registry._handle_entry_point(_EntryPoint("unknown", object())) == 0

    class _BadEP:
        name = "bad"

    assert registry._register_entry_point_class(_BadEP(), BadAnalyzer) == 0


def test_registry_dependencies_and_order() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="a",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies=set(),
    )
    registry.register(
        name="b",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies={"a"},
    )
    order = registry.resolve_execution_order(["a", "b"])
    assert order == ["a", "b"]

    with pytest.raises(KeyError):
        registry.resolve_execution_order(["missing"])

    registry.register(
        name="c",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies={"b"},
    )
    registry.register(
        name="d",
        analyzer_class=DummyAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies={"c"},
    )
    registry._analyzers["a"].dependencies.add("d")
    with pytest.raises(ValueError):
        registry.resolve_execution_order(["a", "b", "c", "d"])

    with pytest.raises(TypeError):
        registry.get_by_category("bad")  # type: ignore[arg-type]

    assert registry.get_by_category(AnalyzerCategory.METADATA)["b"] is DummyAnalyzer
    assert registry.get_dependencies("b") == {"a"}
    registry.clear()
    assert len(registry) == 0


def test_registry_auto_extract_failure() -> None:
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="bad",
        analyzer_class=BadAnalyzer,
        category=AnalyzerCategory.METADATA,
        auto_extract=True,
    )
    assert registry.get_metadata("bad") is not None
