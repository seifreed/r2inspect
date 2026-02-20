# Schema and Configuration Module Tests - Coverage Summary

## Test Files Created

1. **tests/unit/test_results_models.py** - 59 tests for results_models.py
2. **tests/unit/test_base_schemas.py** - 34 tests for base.py  
3. **tests/unit/test_hashing_schemas.py** - 37 tests for hashing.py
4. **tests/unit/test_format_schemas.py** - 71 tests for format.py
5. **tests/unit/test_config_schemas.py** - 59 tests for schemas.py

**Total: 260 comprehensive tests**

## Coverage Results

| Module | Previous Coverage | New Coverage | Improvement | Lines Missing |
|--------|------------------|--------------|-------------|---------------|
| r2inspect/schemas/results_models.py | 77% (38 lines) | **100%** | +23% | 0 |
| r2inspect/schemas/base.py | 72% (12 lines) | **98%** | +26% | 1 |
| r2inspect/schemas/hashing.py | 47% (19 lines) | **97%** | +50% | 1 |
| r2inspect/schemas/format.py | 58% (53 lines) | **99%** | +41% | 1 |
| r2inspect/config_schemas/schemas.py | 61% (50 lines) | **100%** | +39% | 0 |

## Test Coverage Details

### 1. results_models.py (100% coverage)
Tests cover:
- All dataclass models (FileInfo, HashingResult, ImportInfo, etc.)
- Model creation with defaults and custom values
- Serialization via to_dict() methods
- Business logic methods (has_hash, has_evasion, has_crypto, is_suspicious)
- Complex nested model serialization in AnalysisResult
- Timestamp handling and datetime serialization
- Summary generation and filtering methods

### 2. base.py (98% coverage)
Tests cover:
- AnalysisResultBase validation and creation
- Field validators (execution_time, analyzer_name)
- Pydantic configuration (extra fields, validation on assignment)
- Serialization methods (model_dump_safe, to_json)
- FileInfoBase with extension normalization
- Error handling and edge cases

### 3. hashing.py (97% coverage)
Tests cover:
- HashAnalysisResult creation for all hash types
- Hash type validation (ssdeep, tlsh, impfuzzy, ccbhash, simhash, telfhash)
- Method validation (python_library, system_binary, r2pipe, direct_read)
- File size validation with boundary testing
- is_valid_hash() method with edge cases
- Case-insensitive normalization

### 4. format.py (99% coverage)
Tests cover:
- SectionInfo validation and creation
- Entropy validation (0.0-8.0 range)
- Permission checking (is_readable, is_writable, is_executable)
- SecurityFeatures with all security flags
- Security score calculation
- FormatAnalysisResult for PE, ELF, Mach-O formats
- Format-specific methods (is_pe, is_elf, is_macho, is_64bit)
- Section filtering methods

### 5. config_schemas/schemas.py (100% coverage)
Tests cover:
- All config dataclasses with defaults and validation
- Boundary testing for numeric values
- Immutability enforcement (frozen=True)
- R2InspectConfig composition and nesting
- to_dict() and from_dict() round-trip serialization
- merge() functionality
- Property methods (VirusTotalConfig.is_configured)
- Validation error handling

## Test Characteristics

All tests follow requirements:
- Simple `def test_*` functions (NO classes)
- Proper naming convention: `test_MODULE_schemas.py` or `test_MODULE_models.py`
- NO mocks - tests use real schema validation
- NO emojis
- Comprehensive coverage of:
  - Schema validation
  - Model creation
  - Serialization/deserialization
  - Configuration parsing
  - Format conversions
  - Edge cases and error handling

## Running the Tests

```bash
# Run all schema tests
pytest tests/unit/test_results_models.py tests/unit/test_base_schemas.py \
       tests/unit/test_hashing_schemas.py tests/unit/test_format_schemas.py \
       tests/unit/test_config_schemas.py -v

# Run with coverage
pytest tests/unit/test_results_models.py tests/unit/test_base_schemas.py \
       tests/unit/test_hashing_schemas.py tests/unit/test_format_schemas.py \
       tests/unit/test_config_schemas.py \
       --cov=r2inspect.schemas.results_models \
       --cov=r2inspect.schemas.base \
       --cov=r2inspect.schemas.hashing \
       --cov=r2inspect.schemas.format \
       --cov=r2inspect.config_schemas.schemas \
       --cov-report=term-missing
```

## Achievement

Target: 95%+ coverage on all modules
**Result: ACHIEVED** - All modules now have 97-100% coverage
