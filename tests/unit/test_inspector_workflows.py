"""Comprehensive tests for core/inspector.py workflows and execution paths."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from r2inspect.core.inspector import R2Inspector


def create_mock_registry():
    """Create a mock registry that supports len()."""
    registry = Mock()
    registry.__len__ = Mock(return_value=5)
    registry.list_analyzers.return_value = []
    return registry


class TestInspectorInitialization:
    """Test R2Inspector initialization and dependency injection."""

    def test_init_with_all_dependencies(self) -> None:
        """Test successful initialization with all required dependencies."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            verbose=False,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        assert inspector.filename == "/tmp/test.bin"
        assert inspector.adapter == mock_adapter
        assert inspector.config == mock_config
        assert inspector.verbose is False
        assert inspector.registry == mock_registry
        mock_file_validator.validate.assert_called_once()

    def test_init_without_memory_monitor_raises(self) -> None:
        """Test initialization fails without memory monitor."""
        with pytest.raises(ValueError, match="memory_monitor must be provided"):
            R2Inspector(filename="/tmp/test.bin", memory_monitor=None)

    def test_init_without_adapter_raises(self) -> None:
        """Test initialization fails without adapter."""
        mock_memory = Mock()
        mock_config = Mock()
        with pytest.raises(ValueError, match="adapter must be provided"):
            R2Inspector(
                filename="/tmp/test.bin", memory_monitor=mock_memory, config=mock_config, adapter=None
            )

    def test_init_without_config_uses_factory(self) -> None:
        """Test config is created from factory when not provided."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            config=None,
            config_factory=lambda: mock_config,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        assert inspector.config == mock_config

    def test_init_without_config_factory_raises(self) -> None:
        """Test initialization fails when config is None and no factory provided."""
        mock_adapter = Mock()
        mock_memory = Mock()
        with pytest.raises(ValueError, match="config_factory must be provided when config is None"):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=mock_adapter,
                memory_monitor=mock_memory,
                config=None,
                config_factory=None,
            )

    def test_init_without_factories_raises(self) -> None:
        """Test initialization fails without required factories."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()

        with pytest.raises(
            ValueError,
            match="file_validator_factory and result_aggregator_factory must be provided",
        ):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=mock_adapter,
                memory_monitor=mock_memory,
                config=mock_config,
                file_validator_factory=None,
                result_aggregator_factory=None,
            )

    def test_init_file_validation_failure(self) -> None:
        """Test initialization fails when file validation fails."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = False

        with pytest.raises(ValueError, match="File validation failed"):
            R2Inspector(
                filename="/tmp/nonexistent.bin",
                adapter=mock_adapter,
                memory_monitor=mock_memory,
                config=mock_config,
                file_validator_factory=lambda _: mock_file_validator,
                result_aggregator_factory=lambda: Mock(),
                registry_factory=lambda: Mock(),
                pipeline_builder_factory=lambda a, r, c, f: Mock(),
            )

    def test_init_without_registry_factory_raises(self) -> None:
        """Test initialization fails without registry_factory."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True

        with pytest.raises(
            ValueError, match="registry_factory and pipeline_builder_factory must be provided"
        ):
            R2Inspector(
                filename="/tmp/test.bin",
                adapter=mock_adapter,
                memory_monitor=mock_memory,
                config=mock_config,
                file_validator_factory=lambda _: mock_file_validator,
                result_aggregator_factory=lambda: Mock(),
                registry_factory=None,
                pipeline_builder_factory=None,
            )


class TestInspectorInfrastructure:
    """Test _init_infrastructure method."""

    def test_init_infrastructure_success(self) -> None:
        """Test infrastructure initialization with registry and pipeline builder."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_registry.__len__ = Mock(return_value=5)
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            verbose=False,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        assert inspector.registry == mock_registry
        assert inspector._pipeline_builder == mock_pipeline_builder

    def test_init_infrastructure_verbose_logging(self) -> None:
        """Test infrastructure initialization with verbose mode logs analyzers."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_registry.__len__ = Mock(return_value=2)
        mock_registry.list_analyzers.return_value = [
            {"name": "pe_analyzer", "category": "format", "file_formats": ["PE"]},
            {"name": "elf_analyzer", "category": "format", "file_formats": ["ELF"]},
        ]
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            verbose=True,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        mock_registry.list_analyzers.assert_called_once()


class TestInspectorAnalyze:
    """Test analyze method and execution workflows."""

    def test_analyze_sequential_execution(self) -> None:
        """Test analyze method with sequential pipeline execution."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_memory.check_memory.return_value = {
            "process_memory_mb": 50.0,
            "peak_memory_mb": 60.0,
            "gc_count": 1,
        }
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline = Mock()
        mock_pipeline.execute.return_value = {"test": "result"}
        mock_pipeline_builder = Mock()
        mock_pipeline_builder.build.return_value = mock_pipeline

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        options = {"batch_mode": True}
        result = inspector.analyze(**options)

        assert "test" in result
        assert result["test"] == "result"
        assert "memory_stats" in result
        assert result["memory_stats"]["initial_memory_mb"] == 50.0
        mock_pipeline_builder.build.assert_called_once_with(options)
        mock_pipeline.execute.assert_called_once_with(options, parallel=False)

    def test_analyze_parallel_execution_thread_safe(self) -> None:
        """Test analyze method with parallel execution when adapter is thread-safe."""
        mock_adapter = Mock()
        mock_adapter.thread_safe = True
        mock_memory = Mock()
        mock_memory.check_memory.return_value = {"process_memory_mb": 50.0}
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = True

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline = Mock()
        mock_pipeline.execute.return_value = {"parallel": "result"}
        mock_pipeline_builder = Mock()
        mock_pipeline_builder.build.return_value = mock_pipeline

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        result = inspector.analyze()

        mock_pipeline.execute.assert_called_once_with({}, parallel=True)
        assert "parallel" in result

    def test_analyze_parallel_disabled_when_not_thread_safe(self) -> None:
        """Test parallel execution is disabled when adapter is not thread-safe."""
        mock_adapter = Mock()
        mock_adapter.thread_safe = False
        mock_memory = Mock()
        mock_memory.check_memory.return_value = {"process_memory_mb": 50.0}
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = True

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline = Mock()
        mock_pipeline.execute.return_value = {}
        mock_pipeline_builder = Mock()
        mock_pipeline_builder.build.return_value = mock_pipeline

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        inspector.analyze()

        mock_pipeline.execute.assert_called_once_with({}, parallel=False)

    def test_analyze_with_progress_callback(self) -> None:
        """Test analyze method with progress callback in sequential mode."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_memory.check_memory.return_value = {"process_memory_mb": 50.0}
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline = Mock()
        mock_pipeline.execute_with_progress.return_value = {"progress": "tracked"}
        mock_pipeline_builder = Mock()
        mock_pipeline_builder.build.return_value = mock_pipeline

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        progress_callback = Mock()
        options = {"detect_packer": True}
        result = inspector.analyze(progress_callback=progress_callback, **options)

        assert result["progress"] == "tracked"
        mock_pipeline.execute_with_progress.assert_called_once_with(progress_callback, options)

    def test_analyze_memory_error_handling(self) -> None:
        """Test analyze handles MemoryError gracefully."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_memory.check_memory.side_effect = [
            {"process_memory_mb": 50.0},
            {"process_memory_mb": 100.0},
        ]
        mock_memory._trigger_gc = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline = Mock()
        mock_pipeline.execute.side_effect = MemoryError("Out of memory")
        mock_pipeline_builder = Mock()
        mock_pipeline_builder.build.return_value = mock_pipeline

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        result = inspector.analyze()

        assert "error" in result
        assert "Memory limit exceeded" in result["error"]
        assert "memory_stats" in result
        mock_memory._trigger_gc.assert_called_once_with(aggressive=True)

    def test_analyze_generic_exception_handling(self) -> None:
        """Test analyze handles generic exceptions gracefully."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_memory.check_memory.return_value = {"process_memory_mb": 50.0}
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline = Mock()
        mock_pipeline.execute.side_effect = RuntimeError("Pipeline failed")
        mock_pipeline_builder = Mock()
        mock_pipeline_builder.build.return_value = mock_pipeline

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        result = inspector.analyze()

        assert "error" in result
        assert "Pipeline failed" in result["error"]

    def test_analyze_pipeline_builder_not_initialized(self) -> None:
        """Test analyze raises when pipeline builder is not initialized."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_memory.check_memory.return_value = {"process_memory_mb": 50.0}
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        inspector._pipeline_builder = None

        result = inspector.analyze()

        assert "error" in result
        assert "Pipeline builder is not initialized" in result["error"]


class TestInspectorCleanup:
    """Test cleanup and context manager functionality."""

    def test_cleanup_with_callback(self) -> None:
        """Test cleanup calls cleanup callback."""
        cleanup_called = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            cleanup_callback=cleanup_callback,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        inspector._cleanup()

        assert len(cleanup_called) == 1
        assert inspector.adapter is None

    def test_cleanup_without_callback(self) -> None:
        """Test cleanup without callback doesn't crash."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            cleanup_callback=None,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        inspector._cleanup()

        assert inspector.adapter is None

    def test_context_manager_enter(self) -> None:
        """Test context manager __enter__ returns self."""
        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        result = inspector.__enter__()

        assert result is inspector

    def test_context_manager_exit_cleanup(self) -> None:
        """Test context manager __exit__ calls cleanup."""
        cleanup_called = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            cleanup_callback=cleanup_callback,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        result = inspector.__exit__(None, None, None)

        assert result is False
        assert len(cleanup_called) == 1

    def test_destructor_cleanup(self) -> None:
        """Test __del__ calls cleanup."""
        cleanup_called = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            cleanup_callback=cleanup_callback,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        inspector.__del__()

        assert len(cleanup_called) == 1

    def test_close_method(self) -> None:
        """Test close method calls cleanup."""
        cleanup_called = []

        def cleanup_callback() -> None:
            cleanup_called.append(True)

        mock_adapter = Mock()
        mock_memory = Mock()
        mock_config = Mock()
        mock_config.typed_config.pipeline.parallel_execution = False

        mock_file_validator = Mock()
        mock_file_validator.validate.return_value = True
        mock_result_aggregator = Mock()
        mock_registry = create_mock_registry()
        mock_pipeline_builder = Mock()

        inspector = R2Inspector(
            filename="/tmp/test.bin",
            config=mock_config,
            adapter=mock_adapter,
            memory_monitor=mock_memory,
            cleanup_callback=cleanup_callback,
            file_validator_factory=lambda _: mock_file_validator,
            result_aggregator_factory=lambda: mock_result_aggregator,
            registry_factory=lambda: mock_registry,
            pipeline_builder_factory=lambda a, r, c, f: mock_pipeline_builder,
        )

        inspector.close()

        assert len(cleanup_called) == 1
