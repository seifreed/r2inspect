# Group 4 Test Files - Quick Reference

## Test File Overview

| Test File | Tests | Target Module | Focus |
|-----------|-------|--------------|-------|
| `test_inspector_workflows.py` | 23 | `core/inspector.py` | Initialization, analyze(), cleanup |
| `test_r2pipe_adapter_commands.py` | 28 | `adapters/r2pipe_adapter.py` | Commands, caching, error handling |
| `test_validation_edge_cases.py` | 59 | `adapters/validation.py` | Data validation, sanitization |
| `test_pipeline_execution_paths.py` | 44 | `pipeline/analysis_pipeline.py` | Sequential/parallel execution |
| **TOTAL** | **154** | **4 modules** | **Core infrastructure** |

## Quick Test Commands

```bash
# Run all Group 4 tests
pytest tests/unit/test_inspector_workflows.py \
       tests/unit/test_r2pipe_adapter_commands.py \
       tests/unit/test_validation_edge_cases.py \
       tests/unit/test_pipeline_execution_paths.py -v

# Run with coverage report
pytest tests/unit/test_inspector_workflows.py \
       tests/unit/test_r2pipe_adapter_commands.py \
       tests/unit/test_validation_edge_cases.py \
       tests/unit/test_pipeline_execution_paths.py \
       --cov=r2inspect.core.inspector \
       --cov=r2inspect.adapters.r2pipe_adapter \
       --cov=r2inspect.adapters.validation \
       --cov=r2inspect.pipeline.analysis_pipeline \
       --cov-report=term-missing

# Run individual files
pytest tests/unit/test_inspector_workflows.py -v
pytest tests/unit/test_r2pipe_adapter_commands.py -v
pytest tests/unit/test_validation_edge_cases.py -v
pytest tests/unit/test_pipeline_execution_paths.py -v
```

## Key Test Classes

### test_inspector_workflows.py
- `TestInspectorInitialization` - Dependency injection and validation
- `TestInspectorInfrastructure` - Registry and pipeline setup
- `TestInspectorAnalyze` - Analyze method execution paths
- `TestInspectorCleanup` - Cleanup and context managers

### test_r2pipe_adapter_commands.py
- `TestR2PipeAdapterInitialization` - Init and validation
- `TestR2PipeAdapterCommands` - cmd/cmdj execution
- `TestR2PipeAdapterCachedQuery` - Caching mechanism
- `TestR2PipeAdapterErrorForcing` - Error injection testing
- `TestR2PipeAdapterIntegration` - Integration scenarios

### test_validation_edge_cases.py
- `TestValidateR2Data` - Data type validation
- `TestSanitizeR2Output` - Output sanitization
- `TestIsValidR2Response` - Response validation
- `TestValidateAddress` - Address conversion
- `TestValidateSize` - Size conversion
- `TestValidationEdgeCases` - Boundary conditions

### test_pipeline_execution_paths.py
- `TestAnalysisPipelineBasics` - Stage management
- `TestSequentialExecution` - Sequential mode
- `TestParallelExecution` - Parallel mode
- `TestStageTimeout` - Timeout handling
- `TestProgressCallback` - Progress tracking
- `TestEffectiveWorkers` - Worker configuration
- `TestThreadSafeContext` - Thread safety
- `TestPipelineErrorHandling` - Error scenarios

## Coverage Targets

| Module | Before | Target | Improvement |
|--------|--------|--------|-------------|
| core/inspector.py | 52% | 80-85% | +28-33% |
| adapters/r2pipe_adapter.py | 48% | 85-90% | +37-42% |
| adapters/validation.py | 70% | 95%+ | +25%+ |
| pipeline/analysis_pipeline.py | 77% | 90-95% | +13-18% |

## Special Testing Features

### Mock Helpers
- `create_mock_registry()` - Registry with len() support
- `_MockStage` - Basic stage for testing
- `_FailingStage` - Stage that raises exceptions
- `_SlowStage` - Stage for timeout testing

### Environment Variables
- `R2INSPECT_FORCE_ADAPTER_ERROR` - Force adapter errors
- `R2INSPECT_MAX_WORKERS` - Cap worker count

## Common Test Patterns

### Inspector Testing
```python
mock_adapter = Mock()
mock_memory = Mock()
mock_config = Mock()
mock_file_validator = Mock()
mock_file_validator.validate.return_value = True

inspector = R2Inspector(
    filename="/tmp/test.bin",
    adapter=mock_adapter,
    memory_monitor=mock_memory,
    config=mock_config,
    file_validator_factory=lambda _: mock_file_validator,
    ...
)
```

### Adapter Testing
```python
mock_r2 = Mock()
adapter = R2PipeAdapter(mock_r2)

# Test caching
adapter._cache["iSj"] = [{"cached": "data"}]
result = adapter._cached_query("iSj", "list")
```

### Validation Testing
```python
# Test data validation
result = validate_r2_data(data, "dict")
assert isinstance(result, dict)

# Test sanitization
clean = sanitize_r2_output(raw_text)
assert "\x1b" not in clean
```

### Pipeline Testing
```python
pipeline = AnalysisPipeline()
pipeline.add_stage(_MockStage("stage1"))

# Sequential
result = pipeline.execute(parallel=False)

# Parallel
result = pipeline.execute_parallel()
```

## Files Created

1. `tests/unit/test_inspector_workflows.py` - 637 lines
2. `tests/unit/test_r2pipe_adapter_commands.py` - 497 lines
3. `tests/unit/test_validation_edge_cases.py` - 455 lines
4. `tests/unit/test_pipeline_execution_paths.py` - 563 lines

**Total:** ~2,152 lines of comprehensive test code
