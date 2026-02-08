import sys
from abc import ABCMeta
from importlib.metadata import EntryPoint

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import (
    AnalyzerCategory,
    AnalyzerMetadata,
    AnalyzerRegistry,
)
from r2inspect.registry.default_registry import (
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)


class _TestAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {"available": True}

    def get_category(self) -> str:
        return "metadata"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        return "Test analyzer"


class _OtherAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {"available": True}

    def get_category(self) -> str:
        return "hashing"

    def get_supported_formats(self) -> set[str]:
        return {"ELF"}

    def get_description(self) -> str:
        return "Other analyzer"


class _ExplodingAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {"available": False}

    def get_category(self) -> str:
        return "metadata"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def get_description(self) -> str:
        raise RuntimeError("boom")


class _AbstractAnalyzer(BaseAnalyzer):
    pass


class _NoAnalyzeMeta(ABCMeta):
    def __getattribute__(cls, name: str):
        if name == "analyze":
            raise AttributeError("no analyze")
        return super().__getattribute__(name)


class _NoAnalyzeAnalyzer(BaseAnalyzer, metaclass=_NoAnalyzeMeta):
    def analyze(self) -> dict:
        return {"available": False}


class _NoInitMeta(ABCMeta):
    def __getattribute__(cls, name: str):
        if name == "__init__":
            raise AttributeError("no init")
        return super().__getattribute__(name)


class _NoInitAnalyzer(metaclass=_NoInitMeta):
    pass


def test_analyzer_metadata_validation_and_to_dict():
    with pytest.raises(ValueError):
        AnalyzerMetadata(name="", analyzer_class=_TestAnalyzer, category=AnalyzerCategory.METADATA)

    with pytest.raises(ValueError):
        AnalyzerMetadata(name="bad", analyzer_class=None, category=AnalyzerCategory.METADATA)

    with pytest.raises(TypeError):
        AnalyzerMetadata(name="bad", analyzer_class=_TestAnalyzer, category="nope")  # type: ignore[arg-type]

    metadata = AnalyzerMetadata(
        name="test",
        analyzer_class=_TestAnalyzer,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        required=True,
        dependencies={"other"},
        description="desc",
    )
    assert metadata.supports_format("pe") is True
    assert metadata.supports_format("ELF") is False

    info = metadata.to_dict()
    assert info["name"] == "test"
    assert info["category"] == "metadata"
    assert "PE" in info["file_formats"]


def test_registry_validate_and_register_eager_auto_extract():
    registry = AnalyzerRegistry(lazy_loading=False)

    is_valid, error = registry.validate_analyzer(_TestAnalyzer)
    assert is_valid is True
    assert error is None

    registry.register(
        name="test",
        analyzer_class=_TestAnalyzer,
        required=True,
    )
    assert registry.is_registered("test") is True
    metadata = registry.get_metadata("test")
    assert metadata is not None
    assert metadata.category == AnalyzerCategory.METADATA
    assert metadata.required is True

    is_valid, error = registry.validate_analyzer(_AbstractAnalyzer)
    assert is_valid is False
    assert "abstract" in (error or "")

    is_valid, error = registry.validate_analyzer(_TestAnalyzer())
    assert is_valid is False
    assert "class" in (error or "")

    is_valid, error = registry.validate_analyzer(_NoAnalyzeAnalyzer)
    assert is_valid is False
    assert "analyze" in (error or "")

    is_valid, error = registry.validate_analyzer(_NoInitAnalyzer)
    assert is_valid is False
    assert "__init__" in (error or "")


def test_registry_parse_category_and_extract_errors():
    registry = AnalyzerRegistry(lazy_loading=False)
    assert registry._parse_category(AnalyzerCategory.METADATA) == AnalyzerCategory.METADATA

    with pytest.raises(ValueError):
        registry._parse_category("nope")

    with pytest.raises(TypeError):
        registry._parse_category(123)

    with pytest.raises(ValueError):
        registry.extract_metadata_from_class(type("NotAnalyzer", (), {}))

    with pytest.raises(RuntimeError):
        registry.extract_metadata_from_class(_ExplodingAnalyzer)

    category, formats, description = registry._auto_extract_metadata(
        analyzer_class=_ExplodingAnalyzer,
        name="explode",
        category=None,
        file_formats=None,
        description="",
        auto_extract=True,
    )
    assert category is None
    assert formats is None
    assert description == ""

    assert registry.is_base_analyzer(_TestAnalyzer()) is False


def test_registry_register_from_instance_and_dependencies():
    registry = AnalyzerRegistry(lazy_loading=False)
    instance = _TestAnalyzer(adapter=None, config=None, filepath=None)
    registry.register_from_instance(instance, required=True, dependencies={"dep"})

    deps = registry.get_dependencies(instance.get_name())
    assert "dep" in deps

    with pytest.raises(ValueError):
        registry.register_from_instance(object())


def test_registry_lazy_registration_and_get_analyzer_class(tmp_path):
    module_path = tmp_path / "tmp_entrypoint_module.py"
    module_path.write_text(
        "from r2inspect.abstractions.base_analyzer import BaseAnalyzer\n"
        "class LazyAnalyzer(BaseAnalyzer):\n"
        "    def analyze(self):\n"
        "        return {'available': True}\n"
        "    def get_category(self):\n"
        "        return 'metadata'\n"
        "    def get_supported_formats(self):\n"
        "        return {'PE'}\n"
        "    def get_description(self):\n"
        "        return 'lazy'\n"
    )

    sys.path.insert(0, str(tmp_path))
    try:
        registry = AnalyzerRegistry(lazy_loading=True)
        registry.register(
            name="lazy",
            module_path="tmp_entrypoint_module",
            class_name="LazyAnalyzer",
            category=AnalyzerCategory.METADATA,
            file_formats={"PE"},
        )

        analyzer_class = registry.get_analyzer_class("lazy")
        assert analyzer_class is not None
        assert analyzer_class.__name__ == "LazyAnalyzer"
    finally:
        sys.path.remove(str(tmp_path))


def test_registry_registration_error_paths(tmp_path):
    registry = AnalyzerRegistry(lazy_loading=False)

    with pytest.raises(ValueError):
        registry.register(name="", analyzer_class=_TestAnalyzer, category=AnalyzerCategory.METADATA)

    with pytest.raises(ValueError):
        registry.register(name="bad", analyzer_class=None)

    with pytest.raises(ValueError):
        registry.register(
            name="bad",
            analyzer_class=_TestAnalyzer,
            module_path="some.module",
            class_name="Cls",
            category=AnalyzerCategory.METADATA,
        )

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
        registry._handle_lazy_registration(
            name="x",
            module_path="mod",
            class_name="Cls",
            category=None,
            file_formats=None,
            required=False,
            dependencies=None,
            description="",
        )

    with pytest.raises(ValueError):
        registry._lazy_fallback_analyzer_class(None, None)

    with pytest.raises(ValueError):
        registry._ensure_analyzer_class(None)

    with pytest.raises(ValueError):
        registry._ensure_category(_TestAnalyzer, None)

    module_path = tmp_path / "tmp_lazy_fallback.py"
    module_path.write_text("class FallbackAnalyzer:\n" "    def __init__(self):\n" "        pass\n")
    sys.path.insert(0, str(tmp_path))
    try:
        registry.register(
            name="lazy_fallback",
            module_path="tmp_lazy_fallback",
            class_name="FallbackAnalyzer",
            category=AnalyzerCategory.METADATA,
        )
        assert registry.get_analyzer_class("lazy_fallback").__name__ == "FallbackAnalyzer"
    finally:
        sys.path.remove(str(tmp_path))


def test_registry_is_base_analyzer_import_error():
    registry = AnalyzerRegistry(lazy_loading=False)
    original = sys.modules.get("r2inspect.abstractions.base_analyzer")
    sys.modules["r2inspect.abstractions.base_analyzer"] = None
    registry._base_analyzer_class = None
    try:
        assert registry._get_base_analyzer_class() is None
        assert registry.is_base_analyzer(_TestAnalyzer()) is False
    finally:
        if original is not None:
            sys.modules["r2inspect.abstractions.base_analyzer"] = original
        else:
            del sys.modules["r2inspect.abstractions.base_analyzer"]


def test_registry_filters_and_execution_order():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="a",
        analyzer_class=_TestAnalyzer,
        category=AnalyzerCategory.METADATA,
        required=True,
        file_formats={"PE"},
    )
    registry.register(
        name="b",
        analyzer_class=_OtherAnalyzer,
        category=AnalyzerCategory.HASHING,
        required=False,
        file_formats={"ELF"},
        dependencies={"a"},
    )

    assert "a" in registry.get_analyzers_for_format("PE")
    assert "b" in registry.get_analyzers_for_format("ELF")
    assert "a" in registry.get_by_category(AnalyzerCategory.METADATA)
    assert "a" in registry.get_required_analyzers()
    assert "b" in registry.get_optional_analyzers()

    order = registry.resolve_execution_order(["a", "b"])
    assert order.index("a") < order.index("b")

    with pytest.raises(KeyError):
        registry.resolve_execution_order(["missing"])

    registry.register(
        name="c",
        analyzer_class=_OtherAnalyzer,
        category=AnalyzerCategory.HASHING,
        dependencies={"d"},
    )
    registry.register(
        name="d",
        analyzer_class=_TestAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies={"c"},
    )
    with pytest.raises(ValueError):
        registry.resolve_execution_order(["c", "d"])

    assert registry.get_analyzer_class("missing") is None
    assert registry.unregister("missing") is False
    assert registry.list_analyzers()

    registry.clear()
    assert len(registry) == 0

    assert "a" not in registry


def test_registry_is_base_analyzer_type_error():
    registry = AnalyzerRegistry(lazy_loading=False)
    assert registry.is_base_analyzer(_TestAnalyzer()) is False


def test_registry_entry_points_group_load(tmp_path):
    module_path = tmp_path / "tmp_entrypoint_group.py"
    module_path.write_text(
        "from r2inspect.abstractions.base_analyzer import BaseAnalyzer\n"
        "def register(registry):\n"
        "    registry.register(name='ep_group', analyzer_class=TempAnalyzer, category='metadata')\n"
        "class TempAnalyzer(BaseAnalyzer):\n"
        "    def analyze(self):\n"
        "        return {'available': True}\n"
        "    def get_category(self):\n"
        "        return 'metadata'\n"
        "    def get_supported_formats(self):\n"
        "        return {'PE'}\n"
        "    def get_description(self):\n"
        "        return 'temp'\n"
    )
    dist_info = tmp_path / "tmp_entrypoint_group-0.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: tmp_entrypoint_group\nVersion: 0.0.0\n")
    (dist_info / "entry_points.txt").write_text(
        "[r2inspect.analyzers]\nentry = tmp_entrypoint_group:register\n"
    )

    sys.path.insert(0, str(tmp_path))
    try:
        registry = AnalyzerRegistry(lazy_loading=False)
        loaded = registry.load_entry_points("r2inspect.analyzers")
        assert loaded >= 1
    finally:
        sys.path.remove(str(tmp_path))


def test_entry_points_group_exception():
    from r2inspect.registry import analyzer_registry as registry_module

    registry = AnalyzerRegistry(lazy_loading=False)
    original = registry_module.entry_points

    def _boom():
        raise RuntimeError("boom")

    try:
        registry_module.entry_points = _boom
        assert registry._get_entry_points_group("r2inspect.analyzers") == []
    finally:
        registry_module.entry_points = original


def test_registry_entry_point_non_callable(tmp_path):
    module_path = tmp_path / "tmp_entrypoint_value.py"
    module_path.write_text("VALUE = 5\n")
    sys.path.insert(0, str(tmp_path))
    try:
        registry = AnalyzerRegistry(lazy_loading=False)
        ep_value = EntryPoint(
            name="value",
            value="tmp_entrypoint_value:VALUE",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_value) == 0
    finally:
        sys.path.remove(str(tmp_path))


def test_registry_entry_point_class_failure(tmp_path):
    module_path = tmp_path / "tmp_entrypoint_bad_class.py"
    module_path.write_text(
        "from r2inspect.abstractions.base_analyzer import BaseAnalyzer\n"
        "class BadAnalyzer(BaseAnalyzer):\n"
        "    def __init__(self, *args, **kwargs):\n"
        "        raise RuntimeError('init boom')\n"
        "    def analyze(self):\n"
        "        return {'available': True}\n"
        "    def get_category(self):\n"
        "        return 'metadata'\n"
        "    def get_supported_formats(self):\n"
        "        return {'PE'}\n"
        "    def get_description(self):\n"
        "        return 'bad'\n"
        "class Plain:\n"
        "    pass\n"
    )
    sys.path.insert(0, str(tmp_path))
    try:
        registry = AnalyzerRegistry(lazy_loading=False)
        ep_class = EntryPoint(
            name="bad_class",
            value="tmp_entrypoint_bad_class:BadAnalyzer",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_class) == 0

        ep_plain = EntryPoint(
            name="plain",
            value="tmp_entrypoint_bad_class:Plain",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_plain) == 1
    finally:
        sys.path.remove(str(tmp_path))


def test_registry_dependencies_with_external_dep():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="a",
        analyzer_class=_TestAnalyzer,
        category=AnalyzerCategory.METADATA,
        dependencies={"external"},
    )
    graph, in_degree = registry._build_dependency_graph(["a"])
    registry._calculate_in_degrees(graph, in_degree, ["a"])
    assert in_degree["a"] == 0

    order = registry._topological_sort(graph, in_degree, ["a"])
    assert order == ["a"]

    with pytest.raises(TypeError):
        registry.get_by_category("metadata")  # type: ignore[arg-type]


def test_registry_unregister_success():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="to_remove",
        analyzer_class=_TestAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    assert registry.unregister("to_remove") is True


def test_default_registry_entry_point_failure():
    from r2inspect.registry import analyzer_registry as registry_module

    original = registry_module.AnalyzerRegistry.load_entry_points

    def _boom(self, group: str = "r2inspect.analyzers") -> int:  # noqa: D401
        raise RuntimeError("boom")

    try:
        registry_module.AnalyzerRegistry.load_entry_points = _boom
        registry = create_default_registry()
        assert len(registry) > 0
    finally:
        registry_module.AnalyzerRegistry.load_entry_points = original


def test_registry_entry_point_handling(tmp_path):
    module_path = tmp_path / "tmp_entrypoint_module_ep.py"
    module_path.write_text(
        "from r2inspect.abstractions.base_analyzer import BaseAnalyzer\n"
        "def register(registry):\n"
        "    registry.register(name='ep', analyzer_class=TempAnalyzer, category='metadata')\n"
        "def register_fail(registry):\n"
        "    raise RuntimeError('boom')\n"
        "class TempAnalyzer(BaseAnalyzer):\n"
        "    def analyze(self):\n"
        "        return {'available': True}\n"
        "    def get_category(self):\n"
        "        return 'metadata'\n"
        "    def get_supported_formats(self):\n"
        "        return {'PE'}\n"
        "    def get_description(self):\n"
        "        return 'temp'\n"
    )

    sys.path.insert(0, str(tmp_path))
    try:
        registry = AnalyzerRegistry(lazy_loading=False)

        ep_callable = EntryPoint(
            name="callable",
            value="tmp_entrypoint_module_ep:register",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_callable) == 1
        assert registry.is_registered("ep") is True

        ep_callable_fail = EntryPoint(
            name="callable_fail",
            value="tmp_entrypoint_module_ep:register_fail",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_callable_fail) == 0

        ep_class = EntryPoint(
            name="class",
            value="tmp_entrypoint_module_ep:TempAnalyzer",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_class) == 1

        ep_missing = EntryPoint(
            name="missing",
            value="tmp_entrypoint_module_ep:Missing",
            group="r2inspect.analyzers",
        )
        assert registry._handle_entry_point(ep_missing) == 0
    finally:
        sys.path.remove(str(tmp_path))


def test_default_registry_filters():
    default_registry = create_default_registry()
    assert len(default_registry) > 0

    pe_registry = get_format_specific_analyzers("PE")
    assert len(pe_registry) > 0

    minimal = get_minimal_registry()
    assert len(minimal) > 0

    by_category = get_category_registry(AnalyzerCategory.FORMAT)
    assert len(by_category) > 0
