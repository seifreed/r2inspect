import os
import struct
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.core.r2_session import R2Session
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.exploit_mitigation_analyzer import ExploitMitigationAnalyzer
from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


@pytest.fixture
def pe_fixture_path() -> Path:
    return Path("samples/fixtures/hello_pe.exe")


@pytest.fixture
def elf_fixture_path() -> Path:
    return Path("samples/fixtures/hello_elf")


@pytest.fixture
def pe_adapter(monkeypatch: pytest.MonkeyPatch, pe_fixture_path: Path):
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    session = R2Session(str(pe_fixture_path))
    r2 = session.open(pe_fixture_path.stat().st_size / (1024 * 1024))
    adapter = R2PipeAdapter(r2)
    try:
        yield adapter
    finally:
        session.close()


def test_r2_session_basic_and_safe_mode(monkeypatch: pytest.MonkeyPatch, pe_fixture_path: Path):
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    session = R2Session(str(pe_fixture_path))
    r2 = session.open(pe_fixture_path.stat().st_size / (1024 * 1024))
    assert r2 is not None
    assert session.is_open is True
    assert session._run_basic_info_check() is True
    session.close()
    assert session.is_open is False

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "i")
    session = R2Session(str(pe_fixture_path))
    r2 = session.open(pe_fixture_path.stat().st_size / (1024 * 1024))
    assert r2 is not None
    assert session.is_open is True
    session.close()


def test_r2_session_flags_and_fat_macho_detection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fat = tmp_path / "fat.bin"
    header = struct.pack(">I", 0xCAFEBABE) + struct.pack(">I", 2)
    entry_x86 = struct.pack(">IIIII", 0x01000007, 0, 0, 0, 0)
    entry_arm = struct.pack(">IIIII", 0x0100000C, 0, 0, 0, 0)
    fat.write_bytes(header + entry_x86 + entry_arm)

    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "1")
    session = R2Session(str(fat))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches or "arm64" in arches
    flags = session._select_r2_flags()
    assert "-2" in flags
    assert "-M" in flags
    assert "-NN" in flags


def test_r2_session_analysis_depth_and_timeouts(
    monkeypatch: pytest.MonkeyPatch, pe_fixture_path: Path
) -> None:
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    session = R2Session(str(pe_fixture_path))
    session.open(pe_fixture_path.stat().st_size / (1024 * 1024))

    monkeypatch.setenv("R2INSPECT_ANALYSIS_DEPTH", "0")
    assert session._perform_initial_analysis(0.1) is True

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "aa")
    assert session._run_cmd_with_timeout("aa", 0.01) is False
    session.close()


def test_pipeline_builder_builds_stages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, elf_fixture_path: Path
) -> None:
    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    session = R2Session(str(elf_fixture_path))
    r2 = session.open(elf_fixture_path.stat().st_size / (1024 * 1024))
    adapter = R2PipeAdapter(r2)

    config_path = tmp_path / "config.json"
    config = Config(config_path=str(config_path))
    config.apply_overrides({"pipeline": {"stage_timeout": 1.5}})
    registry = AnalyzerRegistry(lazy_loading=False)
    builder = PipelineBuilder(adapter, registry, config, str(elf_fixture_path))
    pipeline = builder.build({})

    assert len(pipeline) == 8
    assert all(stage.timeout == 1.5 for stage in pipeline.stages)
    session.close()


def test_large_analyzers_on_pe(pe_adapter: R2PipeAdapter) -> None:
    resource = ResourceAnalyzer(pe_adapter).analyze()
    assert resource["available"] is True

    rich = RichHeaderAnalyzer(pe_adapter).analyze()
    assert "available" in rich

    auth = AuthenticodeAnalyzer(pe_adapter).analyze()
    assert "has_signature" in auth

    mitigations = ExploitMitigationAnalyzer(pe_adapter).analyze()
    assert "available" in mitigations

    functions = FunctionAnalyzer(
        pe_adapter, filename="samples/fixtures/hello_pe.exe"
    ).analyze_functions()
    assert "total_functions" in functions
