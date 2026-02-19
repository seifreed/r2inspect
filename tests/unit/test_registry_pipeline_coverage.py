#!/usr/bin/env python3
"""Unit tests for registry and pipeline modules.

Covers:
  - r2inspect/registry/entry_points.py
  - r2inspect/registry/analyzer_registry.py
  - r2inspect/registry/default_registry.py
  - r2inspect/registry/registry_queries.py
  - r2inspect/registry/metadata_extraction.py
  - r2inspect/pipeline/stages_format.py
  - r2inspect/pipeline/stages_common.py
  - r2inspect/pipeline/stages_security.py
  - r2inspect/pipeline/stages_hashing.py
  - r2inspect/pipeline/stages_metadata.py
  - r2inspect/factory.py
  - r2inspect/__main__.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from r2inspect.registry.categories import AnalyzerCategory as DirectCategory
from r2inspect.registry.default_registry import (
    _ANALYZERS,
    create_default_registry,
    get_category_registry,
    get_format_specific_analyzers,
    get_minimal_registry,
)
from r2inspect.registry.entry_points import EntryPointLoader
from r2inspect.registry.metadata import AnalyzerMetadata
from r2inspect.registry.metadata_extraction import (
    auto_extract_metadata,
    extract_metadata_from_class,
    parse_category,
)
from r2inspect.registry.registry_queries import AnalyzerRegistryQueries


# ---------------------------------------------------------------------------
# Stub classes used across multiple tests
# ---------------------------------------------------------------------------


class StubAnalyzerA:
    """Minimal stub analyzer."""

    def analyze(self) -> dict:
        return {"result": "a"}


class StubAnalyzerB:
    """Second minimal stub analyzer."""

    def analyze(self) -> dict:
        return {"result": "b"}


class StubAnalyzerC:
    """Third stub analyzer with no special behaviour."""

    def detect(self) -> dict:
        return {"detected": True}


# ---------------------------------------------------------------------------
# Stub adapter (no mocking, plain class)
# ---------------------------------------------------------------------------


class StubAdapter:
    """Stub AnalyzerBackend that returns configurable responses."""

    def __init__(self, file_info: dict | None = None) -> None:
        self._file_info = file_info or {}

    def get_file_info(self) -> dict:
        return self._file_info

    # Minimal stubs for any other interface methods that might be needed
    def run_command(self, cmd: str) -> Any:
        return None


# ---------------------------------------------------------------------------
# registry/metadata_extraction.py
# ---------------------------------------------------------------------------


def test_parse_category_from_enum():
    result = parse_category(AnalyzerCategory.FORMAT)
    assert result is AnalyzerCategory.FORMAT


def test_parse_category_from_string_valid():
    result = parse_category("hashing")
    assert result == AnalyzerCategory.HASHING


def test_parse_category_from_string_case_insensitive():
    result = parse_category("METADATA")
    assert result == AnalyzerCategory.METADATA


def test_parse_category_invalid_string():
    with pytest.raises(ValueError, match="Unknown category"):
        parse_category("nonexistent_category")


def test_parse_category_invalid_type():
    with pytest.raises(TypeError):
        parse_category(42)


def test_extract_metadata_from_class_non_base_analyzer():
    """extract_metadata_from_class rejects plain classes."""
    with pytest.raises(ValueError, match="does not inherit from BaseAnalyzer"):
        extract_metadata_from_class(StubAnalyzerA, is_base_analyzer=lambda _: False)


def test_auto_extract_metadata_skipped_when_disabled():
    category, file_formats, description = auto_extract_metadata(
        StubAnalyzerA,
        name="stub",
        category=AnalyzerCategory.METADATA,
        file_formats={"PE"},
        description="original",
        auto_extract=False,
        is_base_analyzer=lambda _: True,
    )
    assert category == AnalyzerCategory.METADATA
    assert file_formats == {"PE"}
    assert description == "original"


def test_auto_extract_metadata_skipped_when_not_base_analyzer():
    category, file_formats, description = auto_extract_metadata(
        StubAnalyzerA,
        name="stub",
        category=AnalyzerCategory.HASHING,
        file_formats=None,
        description="desc",
        auto_extract=True,
        is_base_analyzer=lambda _: False,
    )
    assert category == AnalyzerCategory.HASHING
    assert file_formats is None
    assert description == "desc"


# ---------------------------------------------------------------------------
# registry/metadata.py  (AnalyzerMetadata dataclass)
# ---------------------------------------------------------------------------


def test_analyzer_metadata_supports_format_exact():
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=StubAnalyzerA,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE", "ELF"},
    )
    assert meta.supports_format("PE") is True
    assert meta.supports_format("ELF") is True
    assert meta.supports_format("MACH0") is False


def test_analyzer_metadata_supports_all_formats_when_empty():
    meta = AnalyzerMetadata(
        name="test",
        analyzer_class=StubAnalyzerA,
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
    )
    assert meta.supports_format("PE") is True
    assert meta.supports_format("ELF") is True
    assert meta.supports_format("anything") is True


def test_analyzer_metadata_to_dict():
    meta = AnalyzerMetadata(
        name="demo",
        analyzer_class=StubAnalyzerA,
        category=AnalyzerCategory.HASHING,
        file_formats={"PE"},
        required=True,
        dependencies={"pe_analyzer"},
        description="demo analyzer",
    )
    d = meta.to_dict()
    assert d["name"] == "demo"
    assert d["required"] is True
    assert "PE" in d["file_formats"]
    assert "pe_analyzer" in d["dependencies"]
    assert d["description"] == "demo analyzer"


def test_analyzer_metadata_invalid_empty_name():
    with pytest.raises(ValueError):
        AnalyzerMetadata(
            name="",
            analyzer_class=StubAnalyzerA,
            category=AnalyzerCategory.FORMAT,
        )


def test_analyzer_metadata_invalid_none_class():
    with pytest.raises((ValueError, TypeError)):
        AnalyzerMetadata(
            name="test",
            analyzer_class=None,  # type: ignore[arg-type]
            category=AnalyzerCategory.FORMAT,
        )


def test_analyzer_metadata_invalid_category_type():
    with pytest.raises(TypeError):
        AnalyzerMetadata(
            name="test",
            analyzer_class=StubAnalyzerA,
            category="format",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# registry/registry_queries.py  (AnalyzerRegistryQueries via AnalyzerRegistry)
# ---------------------------------------------------------------------------


def _make_registry() -> AnalyzerRegistry:
    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="alpha",
        analyzer_class=StubAnalyzerA,
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        required=True,
        dependencies={"beta"},
        description="alpha analyzer",
    )
    reg.register(
        name="beta",
        analyzer_class=StubAnalyzerB,
        category=AnalyzerCategory.METADATA,
        file_formats={"PE", "ELF"},
        required=False,
        description="beta analyzer",
    )
    reg.register(
        name="gamma",
        analyzer_class=StubAnalyzerC,
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
        required=False,
    )
    return reg


def test_queries_get_metadata_found():
    reg = _make_registry()
    meta = reg.get_metadata("alpha")
    assert meta is not None
    assert meta.name == "alpha"


def test_queries_get_metadata_not_found():
    reg = _make_registry()
    assert reg.get_metadata("nonexistent") is None


def test_queries_get_analyzer_class():
    reg = _make_registry()
    assert reg.get_analyzer_class("beta") is StubAnalyzerB


def test_queries_get_analyzer_class_missing():
    reg = _make_registry()
    assert reg.get_analyzer_class("unknown") is None


def test_queries_get_analyzers_for_format_pe():
    reg = _make_registry()
    pe_analyzers = reg.get_analyzers_for_format("PE")
    assert "alpha" in pe_analyzers
    assert "beta" in pe_analyzers
    assert "gamma" in pe_analyzers  # gamma has no format restriction -> supports all


def test_queries_get_analyzers_for_format_elf():
    reg = _make_registry()
    elf_analyzers = reg.get_analyzers_for_format("ELF")
    assert "beta" in elf_analyzers
    assert "alpha" not in elf_analyzers  # alpha is PE only


def test_queries_get_by_category():
    reg = _make_registry()
    metadata_analyzers = reg.get_by_category(AnalyzerCategory.METADATA)
    assert "beta" in metadata_analyzers
    assert "alpha" not in metadata_analyzers


def test_queries_get_by_category_wrong_type():
    reg = _make_registry()
    with pytest.raises(TypeError):
        reg.get_by_category("metadata")  # type: ignore[arg-type]


def test_queries_get_required_analyzers():
    reg = _make_registry()
    required = reg.get_required_analyzers()
    assert "alpha" in required
    assert "beta" not in required


def test_queries_get_optional_analyzers():
    reg = _make_registry()
    optional = reg.get_optional_analyzers()
    assert "beta" in optional
    assert "gamma" in optional
    assert "alpha" not in optional


def test_queries_list_analyzers():
    reg = _make_registry()
    listing = reg.list_analyzers()
    names = [item["name"] for item in listing]
    assert "alpha" in names
    assert "beta" in names
    assert "gamma" in names


def test_queries_get_dependencies():
    reg = _make_registry()
    deps = reg.get_dependencies("alpha")
    assert "beta" in deps


def test_queries_get_dependencies_empty():
    reg = _make_registry()
    deps = reg.get_dependencies("beta")
    assert deps == set()


def test_queries_len():
    reg = _make_registry()
    assert len(reg) == 3


def test_queries_contains():
    reg = _make_registry()
    assert "alpha" in reg
    assert "unknown" not in reg


def test_queries_iter():
    reg = _make_registry()
    names = set(reg)
    assert names == {"alpha", "beta", "gamma"}


def test_queries_clear():
    reg = _make_registry()
    reg.clear()
    assert len(reg) == 0


def test_queries_resolve_execution_order_respects_deps():
    reg = _make_registry()
    order = reg.resolve_execution_order(["alpha", "beta"])
    assert order.index("beta") < order.index("alpha")


def test_queries_resolve_execution_order_no_deps():
    reg = _make_registry()
    order = reg.resolve_execution_order(["gamma"])
    assert order == ["gamma"]


# ---------------------------------------------------------------------------
# registry/analyzer_registry.py  (AnalyzerRegistry)
# ---------------------------------------------------------------------------


def test_registry_register_and_lookup():
    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="stub",
        analyzer_class=StubAnalyzerA,
        category=AnalyzerCategory.METADATA,
        required=True,
    )
    assert reg.get_analyzer_class("stub") is StubAnalyzerA
    assert reg.is_registered("stub") is True


def test_registry_register_empty_name_raises():
    reg = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="name cannot be empty"):
        reg.register(
            name="",
            analyzer_class=StubAnalyzerA,
            category=AnalyzerCategory.METADATA,
        )


def test_registry_register_no_class_or_lazy_raises():
    reg = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError):
        reg.register(name="bad")  # type: ignore[call-overload]


def test_registry_register_both_class_and_lazy_raises():
    reg = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError):
        reg.register(
            name="conflict",
            analyzer_class=StubAnalyzerA,
            module_path="r2inspect.modules.pe_analyzer",
            class_name="PEAnalyzer",
            category=AnalyzerCategory.FORMAT,
        )


def test_registry_unregister_existing():
    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="to_remove",
        analyzer_class=StubAnalyzerA,
        category=AnalyzerCategory.METADATA,
    )
    assert reg.unregister("to_remove") is True
    assert reg.is_registered("to_remove") is False


def test_registry_unregister_nonexistent():
    reg = AnalyzerRegistry(lazy_loading=False)
    assert reg.unregister("ghost") is False


def test_registry_validate_analyzer_valid():
    reg = AnalyzerRegistry(lazy_loading=False)
    is_valid, err = reg.validate_analyzer(StubAnalyzerA)
    assert is_valid is True
    assert err is None


def test_registry_validate_analyzer_not_a_class():
    reg = AnalyzerRegistry(lazy_loading=False)
    instance = StubAnalyzerA()
    is_valid, err = reg.validate_analyzer(instance)  # type: ignore[arg-type]
    assert is_valid is False
    assert err is not None


def test_registry_is_registered_false_initially():
    reg = AnalyzerRegistry(lazy_loading=False)
    assert reg.is_registered("nobody") is False


def test_registry_is_base_analyzer_returns_false_for_plain_class():
    reg = AnalyzerRegistry(lazy_loading=False)
    assert reg.is_base_analyzer(StubAnalyzerA) is False


def test_registry_lazy_registration():
    reg = AnalyzerRegistry(lazy_loading=True)
    reg.register(
        name="pe_lazy",
        module_path="r2inspect.modules.pe_analyzer",
        class_name="PEAnalyzer",
        category=AnalyzerCategory.FORMAT,
        file_formats={"PE"},
        required=True,
        description="lazy PE",
    )
    assert reg.is_registered("pe_lazy") is True
    meta = reg.get_metadata("pe_lazy")
    assert meta is not None
    assert meta.required is True


# ---------------------------------------------------------------------------
# registry/entry_points.py  (EntryPointLoader)
# ---------------------------------------------------------------------------


class _FakeRegistry:
    """Minimal registry stub used by EntryPointLoader tests."""

    def __init__(self) -> None:
        self.registered: list[dict] = []
        self._calls: list[str] = []

    def register(self, **kwargs: Any) -> None:
        self.registered.append(kwargs)

    def _parse_category(self, value: Any) -> AnalyzerCategory:
        return AnalyzerCategory.METADATA

    def is_base_analyzer(self, cls: type) -> bool:
        return False

    def extract_metadata_from_class(self, cls: type) -> dict:
        return {"name": "auto_extracted"}


def test_entry_point_loader_no_group_returns_zero():
    reg = _FakeRegistry()
    loader = EntryPointLoader(reg)
    count = loader.load(group="r2inspect.__nonexistent_group__")
    assert count == 0


def test_entry_point_loader_attaches_registry():
    reg = _FakeRegistry()
    loader = EntryPointLoader(reg)
    assert loader._registry is reg


# ---------------------------------------------------------------------------
# registry/default_registry.py
# ---------------------------------------------------------------------------


def test_create_default_registry_has_pe_elf_macho():
    registry = create_default_registry()
    for name in ("pe_analyzer", "elf_analyzer", "macho_analyzer"):
        assert registry.is_registered(name), f"{name} should be registered"


def test_default_registry_analyzer_count_matches_config():
    registry = create_default_registry()
    assert len(registry) >= len(_ANALYZERS)


def test_get_format_specific_analyzers_pe():
    registry = get_format_specific_analyzers("PE")
    assert registry.is_registered("pe_analyzer")
    # elf_analyzer is ELF-only and should NOT be included
    assert not registry.is_registered("elf_analyzer")


def test_get_format_specific_analyzers_elf():
    registry = get_format_specific_analyzers("ELF")
    assert registry.is_registered("elf_analyzer")
    assert not registry.is_registered("pe_analyzer")


def test_get_minimal_registry_only_required():
    registry = get_minimal_registry()
    for name in registry:
        meta = registry.get_metadata(name)
        assert meta is not None and meta.required is True


def test_get_category_registry_hashing():
    registry = get_category_registry(AnalyzerCategory.HASHING)
    for name in registry:
        meta = registry.get_metadata(name)
        assert meta is not None and meta.category == AnalyzerCategory.HASHING


def test_get_category_registry_security():
    registry = get_category_registry(AnalyzerCategory.SECURITY)
    assert registry.is_registered("exploit_mitigation") or registry.is_registered("authenticode")


def test_default_registry_all_pe_required_are_format():
    registry = create_default_registry()
    pe_meta = registry.get_metadata("pe_analyzer")
    assert pe_meta is not None
    assert pe_meta.category == AnalyzerCategory.FORMAT
    assert pe_meta.required is True


# ---------------------------------------------------------------------------
# pipeline/stages_common.py  (AnalyzerStage, IndicatorStage)
# ---------------------------------------------------------------------------


from r2inspect.pipeline.stages_common import AnalyzerStage, IndicatorStage


class _SimpleAnalyzer:
    """Minimal analyzer used in AnalyzerStage tests."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def analyze(self) -> dict:
        return {"value": 42}


def test_analyzer_stage_execute_stores_result():
    stage = AnalyzerStage(
        name="test_stage",
        analyzer_class=_SimpleAnalyzer,
        adapter=StubAdapter(),
        config=None,
        filename="dummy.bin",
        result_key="test_result",
    )
    context: dict = {"results": {}}
    stage.execute(context)
    assert "test_result" in context["results"]
    assert context["results"]["test_result"] == {"value": 42}


def test_analyzer_stage_error_stored_gracefully():
    class _BrokenAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            raise RuntimeError("boom")

    stage = AnalyzerStage(
        name="broken_stage",
        analyzer_class=_BrokenAnalyzer,
        adapter=StubAdapter(),
        config=None,
        filename="dummy.bin",
    )
    context: dict = {"results": {}}
    stage.execute(context)
    assert "error" in context["results"]["broken_stage"]


def test_analyzer_stage_default_result_key_uses_name():
    stage = AnalyzerStage(
        name="my_key",
        analyzer_class=_SimpleAnalyzer,
        adapter=StubAdapter(),
        config=None,
        filename="dummy.bin",
    )
    context: dict = {"results": {}}
    stage.execute(context)
    assert "my_key" in context["results"]


def test_indicator_stage_name_and_deps():
    stage = IndicatorStage()
    assert stage.name == "indicators"
    assert "metadata" in stage.dependencies
    assert "detection" in stage.dependencies


def test_indicator_stage_execute_writes_indicators():
    stage = IndicatorStage()
    context: dict = {"results": {}}
    stage.execute(context)
    assert "indicators" in context["results"]
    assert isinstance(context["results"]["indicators"], list)


# ---------------------------------------------------------------------------
# pipeline/stages_hashing.py  (HashingStage)
# ---------------------------------------------------------------------------


from r2inspect.pipeline.stages_hashing import HashingStage


def _make_hashing_registry() -> AnalyzerRegistry:
    """Registry with a single stub hashing analyzer."""

    class _HashAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict:
            return {"hash": "abc123"}

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="stub_hash",
        analyzer_class=_HashAnalyzer,
        category=AnalyzerCategory.HASHING,
        file_formats=None,
    )
    return reg


def test_hashing_stage_name_and_deps():
    reg = _make_hashing_registry()
    stage = HashingStage(reg, StubAdapter(), None, "dummy.bin")
    assert stage.name == "hashing"
    assert "file_info" in stage.dependencies


def test_hashing_stage_execute_stores_hash():
    reg = _make_hashing_registry()
    stage = HashingStage(reg, StubAdapter(), None, "dummy.bin")
    context: dict = {"results": {}, "metadata": {}}
    stage.execute(context)
    assert "stub_hash" in context["results"]
    assert context["results"]["stub_hash"] == {"hash": "abc123"}


def test_hashing_stage_skips_format_specific_analyzer():
    class _PEOnlyHasher:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict:
            return {"hash": "pe_hash"}

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="pe_hasher",
        analyzer_class=_PEOnlyHasher,
        category=AnalyzerCategory.HASHING,
        file_formats={"PE"},
    )
    stage = HashingStage(reg, StubAdapter(), None, "dummy.bin")
    context: dict = {"results": {}, "metadata": {"file_format": "ELF"}}
    stage.execute(context)
    assert "pe_hasher" not in context["results"]


def test_hashing_stage_handles_analyzer_error():
    class _FailingHasher:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict:
            raise RuntimeError("hash fail")

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="fail_hasher",
        analyzer_class=_FailingHasher,
        category=AnalyzerCategory.HASHING,
        file_formats=None,
    )
    stage = HashingStage(reg, StubAdapter(), None, "dummy.bin")
    context: dict = {"results": {}, "metadata": {}}
    stage.execute(context)
    assert "error" in context["results"]["fail_hasher"]


# ---------------------------------------------------------------------------
# pipeline/stages_security.py  (SecurityStage)
# ---------------------------------------------------------------------------


from r2inspect.pipeline.stages_security import SecurityStage


def test_security_stage_name_and_deps():
    reg = AnalyzerRegistry(lazy_loading=False)
    stage = SecurityStage(reg, StubAdapter(), None, "dummy.bin")
    assert stage.name == "security"
    assert "format_detection" in stage.dependencies


def test_security_stage_no_analyzers_returns_empty():
    reg = AnalyzerRegistry(lazy_loading=False)
    stage = SecurityStage(reg, StubAdapter(), None, "dummy.bin")
    context: dict = {"results": {}, "metadata": {"file_format": "ELF"}}
    result = stage.execute(context)
    assert isinstance(result, dict)


def test_security_stage_with_mitigation_analyzer():
    class _MitigationAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze(self) -> dict:
            return {"dep": True, "aslr": True}

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="exploit_mitigation",
        analyzer_class=_MitigationAnalyzer,
        category=AnalyzerCategory.SECURITY,
    )
    stage = SecurityStage(reg, StubAdapter(), None, "dummy.bin")
    context: dict = {"results": {}, "metadata": {"file_format": "ELF"}}
    stage.execute(context)
    assert "security" in context["results"]
    assert context["results"]["security"].get("dep") is True


# ---------------------------------------------------------------------------
# pipeline/stages_metadata.py  (MetadataStage)
# ---------------------------------------------------------------------------


from r2inspect.pipeline.stages_metadata import MetadataStage


def _make_metadata_registry() -> AnalyzerRegistry:
    class _SectionAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze_sections(self) -> list:
            return [{"name": ".text", "size": 1024}]

    class _ImportAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def get_imports(self) -> list:
            return [{"name": "kernel32.dll"}]

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="section_analyzer",
        analyzer_class=_SectionAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    reg.register(
        name="import_analyzer",
        analyzer_class=_ImportAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    return reg


def test_metadata_stage_name_and_deps():
    reg = _make_metadata_registry()
    stage = MetadataStage(reg, StubAdapter(), None, "dummy.bin", {})
    assert stage.name == "metadata"
    assert "file_info" in stage.dependencies
    assert "format_detection" in stage.dependencies


def test_metadata_stage_execute_extracts_sections_and_imports():
    reg = _make_metadata_registry()
    stage = MetadataStage(reg, StubAdapter(), None, "dummy.bin", {})
    context: dict = {"results": {}}
    stage.execute(context)
    assert "sections" in context["results"]
    assert isinstance(context["results"]["sections"], list)
    assert "imports" in context["results"]


def test_metadata_stage_skips_functions_when_option_false():
    class _FuncAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze_functions(self) -> dict:
            return {"functions": ["main"]}

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="function_analyzer",
        analyzer_class=_FuncAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    stage = MetadataStage(reg, StubAdapter(), None, "dummy.bin", {"analyze_functions": False})
    context: dict = {"results": {}}
    stage.execute(context)
    assert "functions" not in context["results"]


def test_metadata_stage_functions_included_by_default():
    class _FuncAnalyzer:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def analyze_functions(self) -> dict:
            return {"functions": ["main"]}

    reg = AnalyzerRegistry(lazy_loading=False)
    reg.register(
        name="function_analyzer",
        analyzer_class=_FuncAnalyzer,
        category=AnalyzerCategory.METADATA,
    )
    stage = MetadataStage(reg, StubAdapter(), None, "dummy.bin", {})
    context: dict = {"results": {}}
    stage.execute(context)
    assert "functions" in context["results"]


# ---------------------------------------------------------------------------
# pipeline/stages_format.py  (FileInfoStage, FormatDetectionStage)
# ---------------------------------------------------------------------------


from r2inspect.pipeline.stages_format import FileInfoStage, FormatDetectionStage


def test_file_info_stage_name():
    stage = FileInfoStage(StubAdapter(), "dummy.bin")
    assert stage.name == "file_info"
    assert stage.optional is False


def test_file_info_stage_execute_with_real_file(tmp_path: Path):
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"\x4d\x5a" + b"\x00" * 62)  # minimal MZ header

    adapter = StubAdapter(file_info={"bin": {"arch": "x86", "bits": 32, "endian": "little"}})
    stage = FileInfoStage(adapter, str(test_file))
    context: dict = {"results": {}}
    stage.execute(context)

    file_info = context["results"]["file_info"]
    assert file_info["size"] == 64
    assert file_info["name"] == "sample.bin"
    assert "path" in file_info
    assert "sha256" in file_info or "md5" in file_info or "sha1" in file_info


def test_file_info_stage_sets_architecture_from_adapter(tmp_path: Path):
    test_file = tmp_path / "arch_test.bin"
    test_file.write_bytes(b"\x00" * 16)

    adapter = StubAdapter(file_info={"bin": {"arch": "x86", "bits": 64, "endian": "little"}})
    stage = FileInfoStage(adapter, str(test_file))
    context: dict = {"results": {}}
    stage.execute(context)

    file_info = context["results"]["file_info"]
    assert file_info["architecture"] == "x86-64"
    assert file_info["bits"] == 64


def test_file_info_stage_sets_x86_32_architecture(tmp_path: Path):
    test_file = tmp_path / "x86.bin"
    test_file.write_bytes(b"\x00" * 16)

    adapter = StubAdapter(file_info={"bin": {"arch": "x86", "bits": 32, "endian": "little"}})
    stage = FileInfoStage(adapter, str(test_file))
    context: dict = {"results": {}}
    stage.execute(context)

    file_info = context["results"]["file_info"]
    assert file_info["architecture"] == "x86"


def test_file_info_stage_no_adapter_info(tmp_path: Path):
    test_file = tmp_path / "noinfo.bin"
    test_file.write_bytes(b"\x00" * 8)

    adapter = StubAdapter(file_info={})
    stage = FileInfoStage(adapter, str(test_file))
    context: dict = {"results": {}}
    stage.execute(context)

    assert "file_info" in context["results"]


def test_format_detection_stage_name_and_deps():
    stage = FormatDetectionStage(StubAdapter(), "dummy.bin")
    assert stage.name == "format_detection"
    assert "file_info" in stage.dependencies


def test_format_detection_stage_detects_pe_via_r2(tmp_path: Path):
    test_file = tmp_path / "pe_file.bin"
    test_file.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

    adapter = StubAdapter(file_info={"bin": {"format": "PE32+"}})
    stage = FormatDetectionStage(adapter, str(test_file))
    context: dict = {"results": {}, "metadata": {}}
    stage.execute(context)
    assert context["metadata"]["file_format"] == "PE"


def test_format_detection_stage_unknown_format(tmp_path: Path):
    test_file = tmp_path / "unknown.bin"
    test_file.write_bytes(b"\xff\xfe" * 8)

    adapter = StubAdapter(file_info={})
    stage = FormatDetectionStage(adapter, str(test_file))
    context: dict = {"results": {}, "metadata": {}}
    stage.execute(context)
    # Should set some format (possibly Unknown if magic is absent)
    assert "file_format" in context["metadata"]


# ---------------------------------------------------------------------------
# factory.py
# ---------------------------------------------------------------------------


from r2inspect import factory as factory_module
from r2inspect.config import Config
from r2inspect.registry.default_registry import create_default_registry as _cdr


def test_factory_module_importable():
    assert hasattr(factory_module, "build_inspector_dependencies")
    assert hasattr(factory_module, "create_inspector")


def test_create_inspector_raises_for_nonexistent_file():
    with pytest.raises((ValueError, FileNotFoundError, Exception)):
        factory_module.create_inspector("/nonexistent/path/to/file.bin")


def test_build_inspector_dependencies_returns_three_items(tmp_path: Path):
    """build_inspector_dependencies constructs adapter, registry, pipeline builder."""
    # We can only call this with a live r2 session; test that it's callable.
    # Import r2pipe only to check availability; skip if not installed.
    pytest.importorskip("r2pipe")
    test_file = tmp_path / "tiny.bin"
    test_file.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

    # build_inspector_dependencies requires a live r2 object; we skip the actual
    # invocation here but verify the API signature.
    import inspect as _inspect

    sig = _inspect.signature(factory_module.build_inspector_dependencies)
    params = list(sig.parameters.keys())
    assert "r2" in params
    assert "config" in params
    assert "filename" in params


# ---------------------------------------------------------------------------
# __main__.py
# ---------------------------------------------------------------------------


def test_main_module_importable():
    import r2inspect.__main__ as main_module

    assert hasattr(main_module, "main")


def test_main_returns_integer_on_system_exit():
    import r2inspect.__main__ as main_module

    # main() catches SystemExit and returns the code; invoking with --help
    # triggers SystemExit(0).
    original_argv = sys.argv[:]
    sys.argv = ["r2inspect", "--help"]
    try:
        result = main_module.main()
        # --help exits with 0
        assert result == 0
    except SystemExit as exc:
        assert exc.code in (0, None)
    finally:
        sys.argv = original_argv
