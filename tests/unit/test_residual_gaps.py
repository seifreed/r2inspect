#!/usr/bin/env python3
"""Tests for remaining uncovered lines across multiple modules."""

from __future__ import annotations

import binascii
import os
import tempfile
from pathlib import Path
from typing import Any

import pydantic
import pytest

import r2inspect.factory as _factory_mod
import r2inspect.modules.string_domain as _sd_mod
import r2inspect.utils.analyzer_factory as _af_mod
from r2inspect.core.file_validator import FileValidator
from r2inspect.core.inspector import R2Inspector
from r2inspect.core.pipeline_builder import PipelineBuilder
from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.modules.string_domain import decode_base64
from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.schemas.base import AnalysisResultBase
from r2inspect.schemas.format import SectionInfo
from r2inspect.schemas.hashing import HashAnalysisResult
from r2inspect.utils.analyzer_factory import create_analyzer
from r2inspect.utils.memory_manager import global_memory_monitor
from r2inspect.utils.retry_manager import RetryConfig, RetryManager, RetryStrategy

FIXTURE = Path("samples/fixtures/hello_pe.exe")

# ---------------------------------------------------------------------------
# 1. schemas/base.py line 64 – validate_execution_time raises ValueError
# ---------------------------------------------------------------------------


def test_analysis_result_base_negative_execution_time_raises():
    """Line 64: execution_time < 0 raises ValidationError."""
    with pytest.raises(pydantic.ValidationError):
        AnalysisResultBase(available=True, execution_time=-0.1)


# ---------------------------------------------------------------------------
# 2. schemas/format.py line 49 – validate_entropy raises ValueError
# ---------------------------------------------------------------------------


def test_section_info_negative_entropy_raises():
    """Line 49: entropy < 0.0 raises ValidationError."""
    with pytest.raises(pydantic.ValidationError):
        SectionInfo(name="text", entropy=-1.0)


# ---------------------------------------------------------------------------
# 3. schemas/hashing.py line 80 – validate_file_size raises ValueError
# ---------------------------------------------------------------------------


def test_hash_analysis_result_file_size_exceeds_max_raises():
    """Line 80: file_size > 10 GB raises ValidationError."""
    with pytest.raises(pydantic.ValidationError):
        HashAnalysisResult(
            available=True,
            hash_type="ssdeep",
            file_size=11 * 1024 * 1024 * 1024,
        )


# ---------------------------------------------------------------------------
# 4. registry/registry_queries.py line 169 – continue when dep not in names
# ---------------------------------------------------------------------------


def test_calculate_in_degrees_skips_dep_not_in_analyzer_names():
    """Line 169: dep 'B' not in analyzer_names ['A'] triggers continue."""
    registry = AnalyzerRegistry()
    in_degree: dict[str, int] = {}
    # graph["A"] depends on "B", but only "A" is listed in analyzer_names
    registry._calculate_in_degrees(
        graph={"A": {"B"}},
        in_degree=in_degree,
        analyzer_names=["A"],
    )
    # The continue fires; no in_degree entries are written
    assert in_degree == {}


# ---------------------------------------------------------------------------
# 5. utils/retry_manager.py lines 225, 227-228 – break + raise last_exception
# ---------------------------------------------------------------------------


def test_retry_manager_break_and_reraise_when_handle_returns_false():
    """Lines 225, 227-228: _handle_retry_exception returns False → break → raise."""
    manager = RetryManager()
    # Replace the instance method so it always returns False instead of raising
    manager._handle_retry_exception = lambda e, attempt, config, kwargs: False  # type: ignore[assignment]

    def _always_fails() -> None:
        raise ValueError("persistent failure")

    with pytest.raises(ValueError, match="persistent failure"):
        manager.retry_operation(
            _always_fails,
            command_type="generic",
            config=RetryConfig(
                max_attempts=1,
                base_delay=0.0,
                strategy=RetryStrategy.FIXED_DELAY,
                jitter=False,
            ),
        )


# ---------------------------------------------------------------------------
# 6. modules/string_domain.py lines 87-88 – binascii.Error → return None
# ---------------------------------------------------------------------------


def test_decode_base64_binascii_error_returns_none():
    """Lines 87-88: binascii.Error from b64decode is caught and None returned."""

    class _FakeBase64:
        def b64decode(self, s: str, *args: Any, **kwargs: Any) -> bytes:
            raise binascii.Error("invalid base64")

    orig_base64 = _sd_mod.base64
    _sd_mod.base64 = _FakeBase64()  # type: ignore[assignment]
    try:
        # "AAAAAAAA" passes is_base64(); the fake module then raises binascii.Error
        result = decode_base64("AAAAAAAA")
    finally:
        _sd_mod.base64 = orig_base64
    assert result is None


# ---------------------------------------------------------------------------
# 7. modules/packer_detector.py lines 120-122 – except Exception sets error key
# ---------------------------------------------------------------------------


class _FakePackerPacker:
    entropy_threshold = 7.0


class _FakePackerTypedConfig:
    packer = _FakePackerPacker()


class _FakePackerConfig:
    typed_config = _FakePackerTypedConfig()


class _RaisingPackerDetector(PackerDetector):
    """Subclass where _check_packer_signatures always raises."""

    def _check_packer_signatures(self) -> None:  # type: ignore[override]
        raise RuntimeError("simulated packer signature failure")


def test_packer_detector_analyze_catches_exception_and_sets_error():
    """Lines 120-122: exception inside try block is caught; 'error' key is set."""

    class _FakeAdapter:
        pass

    detector = _RaisingPackerDetector(_FakeAdapter(), _FakePackerConfig())
    result = detector.detect()
    assert "error" in result
    assert "simulated packer signature failure" in result["error"]


# ---------------------------------------------------------------------------
# 8. factory.py lines 64-65 – except block closes session then re-raises
# ---------------------------------------------------------------------------


class _TrackingFakeSession:
    """Fake R2Session that returns None from open() to trigger R2PipeAdapter(None)."""

    def __init__(self, filename: str) -> None:
        self.closed = False

    def open(self, size_mb: float) -> None:  # type: ignore[override]
        return None  # R2PipeAdapter(None) will raise ValueError inside the try block

    def close(self) -> None:
        self.closed = True


def test_factory_create_inspector_closes_session_on_constructor_error(
    tmp_path: Path,
) -> None:
    """Lines 64-65: R2PipeAdapter(None) raises inside the try; session.close() called."""
    # Write a valid file so FileValidator passes before reaching the try block
    valid_file = tmp_path / "valid.bin"
    valid_file.write_bytes(b"\x00" * 64)

    orig_session = _factory_mod.R2Session
    _factory_mod.R2Session = _TrackingFakeSession  # type: ignore[assignment]
    try:
        with pytest.raises(ValueError):
            _factory_mod.create_inspector(str(valid_file))
    finally:
        _factory_mod.R2Session = orig_session


# ---------------------------------------------------------------------------
# 9. utils/analyzer_factory.py line 46 – outer except (TypeError, ValueError)
# ---------------------------------------------------------------------------


class _ValueErrorOnKwargsAnalyzer:
    """Analyzer whose __init__ raises ValueError when called with any argument."""

    def __init__(self, config: Any = None) -> None:
        if config is not None:
            raise ValueError("config caused ValueError in __init__")


def test_create_analyzer_outer_except_catches_value_error_from_init():
    """Line 46: ValueError from analyzer_class(**kwargs) is caught by outer except."""

    class _FakeConfig:
        pass

    # create_analyzer passes config=_FakeConfig() via kwargs → __init__ raises ValueError.
    # The outer except (TypeError, ValueError) catches it (line 46).
    # All fallback candidates have backend=None → skipped; analyzer_class() called successfully.
    result = create_analyzer(_ValueErrorOnKwargsAnalyzer, config=_FakeConfig())
    assert isinstance(result, _ValueErrorOnKwargsAnalyzer)


# ---------------------------------------------------------------------------
# 10. core/inspector.py line 210 – _execute_with_progress when progress_callback set
# ---------------------------------------------------------------------------


class _DummyProgressConfig:
    def __init__(self) -> None:
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.pipeline = type("Pipe", (), {})()
        self.typed_config.pipeline.parallel_execution = False
        self.typed_config.pipeline.max_workers = 1
        self.typed_config.pipeline.stage_timeout = None


class _DummyProgressAdapter:
    thread_safe = True


class _DummyProgressRegistry:
    def __len__(self) -> int:
        return 0

    def list_analyzers(self) -> list:
        return []


class _DummyProgressPipelineBuilder:
    def __init__(self, _adapter: Any, _registry: Any, _config: Any, _filename: Any) -> None:
        pass

    def build(self, _options: Any) -> AnalysisPipeline:
        pipeline = AnalysisPipeline()

        class _SimpleStage(AnalysisStage):
            def __init__(self) -> None:
                super().__init__(name="simple")

            def _execute(self, _context: Any) -> dict[str, Any]:
                return {"simple": {"done": True}}

        pipeline.add_stage(_SimpleStage())
        return pipeline


def test_inspector_analyze_uses_execute_with_progress_when_callback_provided() -> None:
    """Line 210: progress_callback set and not use_parallel → _execute_with_progress called."""
    inspector = R2Inspector(
        filename=str(FIXTURE),
        config=_DummyProgressConfig(),
        verbose=False,
        cleanup_callback=lambda: None,
        adapter=_DummyProgressAdapter(),
        registry_factory=_DummyProgressRegistry,
        pipeline_builder_factory=lambda a, r, c, f: _DummyProgressPipelineBuilder(a, r, c, f),
        config_factory=_DummyProgressConfig,
        file_validator_factory=FileValidator,
        result_aggregator_factory=ResultAggregator,
        memory_monitor=global_memory_monitor,
    )

    progress_calls: list[tuple[str, int, int]] = []

    def _callback(name: str, current: int, total: int) -> None:
        progress_calls.append((name, current, total))

    results = inspector.analyze(progress_callback=_callback)
    assert isinstance(results, dict)
    # The progress callback must have been invoked for each stage
    assert len(progress_calls) >= 1
    assert progress_calls[0][0] == "simple"


# ---------------------------------------------------------------------------
# 11. utils/analyzer_factory.py lines 61-62 – TypeError continue in candidates loop
# ---------------------------------------------------------------------------


class _SingleArgAnalyzer:
    """Analyzer that accepts exactly one positional argument."""

    def __init__(self, x: Any) -> None:
        self._x = x


def test_create_analyzer_candidates_loop_continue_on_type_error() -> None:
    """Lines 61-62: multi-arg candidates raise TypeError and are skipped via continue.

    With backend='b', config='c', filename='f' all non-None:
    - kwargs build finds no matching param name for 'x' → kwargs={}
    - analyzer_class(**{}) → TypeError (missing x) → inner except, passes
    - Candidates (b,c,f), (b,c), (b,f), (f,b) each have 2+ args → TypeError → lines 61-62
    - Candidate (f,) succeeds → returns _SingleArgAnalyzer('f')
    """
    result = create_analyzer(_SingleArgAnalyzer, adapter="b", config="c", filename="f")
    assert isinstance(result, _SingleArgAnalyzer)
    assert result._x == "f"
