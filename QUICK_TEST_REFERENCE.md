# Quick Test Reference

## Run All New Core Tests
```bash
pytest tests/unit/test_inspector_helpers_pipeline.py \
       tests/unit/test_pipeline_builder_construction.py \
       tests/unit/test_result_aggregator_validation.py \
       tests/unit/test_file_validator_validation.py -v
```

## Check Coverage
```bash
pytest tests/unit/test_inspector_helpers_pipeline.py \
       tests/unit/test_pipeline_builder_construction.py \
       tests/unit/test_result_aggregator_validation.py \
       tests/unit/test_file_validator_validation.py \
       --cov=r2inspect.core.inspector_helpers \
       --cov=r2inspect.core.pipeline_builder \
       --cov=r2inspect.core.result_aggregator \
       --cov=r2inspect.core.file_validator \
       --cov-report=term-missing
```

## Individual Test Files

### Inspector Helpers (57 tests)
```bash
pytest tests/unit/test_inspector_helpers_pipeline.py -v
```

### Pipeline Builder (30 tests)
```bash
pytest tests/unit/test_pipeline_builder_construction.py -v
```

### Result Aggregator (46 tests)
```bash
pytest tests/unit/test_result_aggregator_validation.py -v
```

### File Validator (55 tests)
```bash
pytest tests/unit/test_file_validator_validation.py -v
```

## Coverage Results
- inspector_helpers.py: 100%
- pipeline_builder.py: 100%
- result_aggregator.py: 100%
- file_validator.py: 100%

## Total: 188 Tests
