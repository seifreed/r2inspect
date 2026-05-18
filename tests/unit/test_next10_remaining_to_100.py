"""Targeted tests for remaining misses in next-10 global block."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from r2inspect.config import Config
from r2inspect.modules.pe_imports import calculate_imphash
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.entry_points import EntryPointLoader
import r2inspect.infrastructure.file_type as file_type


class _Logger:
    def __init__(self) -> None:
        self.debug_messages: list[str] = []
        self.error_messages: list[str] = []

    def debug(self, msg: str) -> None:
        self.debug_messages.append(msg)

    def error(self, msg: str) -> None:
        self.error_messages.append(msg)


def test_config_merge_scalar_override_and_from_dict(tmp_path) -> None:
    cfg = Config(config_path=str(tmp_path / "cfg.json"))
    merged = Config._merge_config({"general": {"verbose": False}}, {"general": "override"})
    assert merged["general"] == "override"

    from_dict_cfg = cfg.from_dict({"general": {"verbose": True}})
    assert isinstance(from_dict_cfg, Config)
    assert from_dict_cfg is not cfg
    assert from_dict_cfg.config_path == cfg.config_path
    assert from_dict_cfg.typed_config.general.verbose is True


def test_file_type_pe_and_elf_outer_error_paths() -> None:
    class _RaisingLogger:
        def debug(self, _msg: str) -> None:
            raise RuntimeError("debug failed")

        def error(self, _msg: str) -> None:
            return None

    # is_pe_file lines 53-57: error in `ij` path and outer catch path
    assert (
        file_type.is_pe_file(
            filepath=None,
            adapter=None,
            r2_instance=None,
            logger=_RaisingLogger(),
            cmdj=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("ij")),
        )
        is False
    )

    # is_elf_file lines 96-97: outer catch path after nested failure
    class _FS:
        @staticmethod
        def read_bytes(_filepath: Any, size: int) -> bytes:
            raise RuntimeError(f"read {size} failed")

    assert (
        file_type.is_elf_file(
            filepath="x.bin",
            adapter=None,
            r2_instance=None,
            logger=_RaisingLogger(),
            cmd=lambda *_args, **_kwargs: "",
            cmdj=lambda *_args, **_kwargs: {},
            file_system=_FS(),
        )
        is False
    )


def test_pe_imports_no_valid_strings_branch() -> None:
    logger = _Logger()
    value = calculate_imphash(
        adapter=SimpleNamespace(get_imports=lambda: [{"name": "CreateFileA"}]),
        logger=logger,
        group_fn=lambda _imports: {"kernel32.dll": [None]},
    )
    assert value == ""
    assert any("No valid import strings found" in msg for msg in logger.debug_messages)


class _FixedSimHash(SimHashAnalyzer):
    """SimHashAnalyzer whose analyze() yields a fixed integer hash."""

    def analyze(self) -> dict[str, Any]:
        return {"available": True, "hash_value": 0x1234}


def test_simhash_calculate_similarity_with_integer_hash() -> None:
    analyzer = _FixedSimHash(adapter=None, filepath="dummy.bin")
    result = analyzer.calculate_similarity(0x1234, hash_type="combined")
    assert result.get("distance") == 0
    assert result.get("current_hash") == hex(0x1234)


def test_analyzer_registry_entry_point_loader_hooks() -> None:
    registry = AnalyzerRegistry()
    loader = EntryPointLoader(registry)

    # Callable entry point: success returns 1 and is invoked with the registry.
    calls: list[Any] = []
    assert (
        loader._register_entry_point_callable(
            SimpleNamespace(name="ok"), lambda reg: calls.append(reg)
        )
        == 1
    )
    assert calls == [registry]

    # A raising callable is swallowed and returns 0.
    def _boom(_reg: Any) -> None:
        raise RuntimeError("callable failed")

    assert loader._register_entry_point_callable(SimpleNamespace(name="bad"), _boom) == 0

    # Non-BaseAnalyzer object derives the name from the entry point itself.
    class _NotAnalyzer:
        pass

    assert (
        loader._derive_entry_point_name(SimpleNamespace(name="plain-ep"), _NotAnalyzer)
        == "plain-ep"
    )
