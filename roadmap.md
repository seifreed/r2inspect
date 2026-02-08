# Test Roadmap

<!-- markdownlint-disable MD013 -->

This roadmap enumerates test coverage needed to fully cover the project. It is organized in phases so you can land value early and build toward full coverage.

Legend:

- [ ] not started
- [~] in progress
- [x] done

## Phase 0 - Test foundations

- [x] Create `tests/` layout with pytest discovery (`tests/unit`, `tests/integration`, `tests/e2e`, `tests/fixtures`)
- [x] Add `tests/conftest.py` with shared fixtures (temp dirs, sample binaries, fake r2pipe, deterministic clock)
- [x] Add CI-friendly markers (`unit`, `integration`, `slow`, `requires_r2`, `requires_*`)
- [x] Add minimal smoke test to ensure pytest discovery works
- [x] Define golden-output strategy (snapshots or JSON fixtures)
- [x] Document how to run tests locally and in CI

## Phase 1 - Core unit tests (fast, no external deps)

### Core runtime

- [x] `r2inspect/core/file_validator.py` input validation and error paths
- [x] `r2inspect/core/r2_session.py` session lifecycle, error handling, timeout paths
- [x] `r2inspect/core/inspector.py` orchestration logic with mocked analyzers
- [x] `r2inspect/core/pipeline_builder.py` stage assembly, optional/required logic
- [x] `r2inspect/core/result_aggregator.py` merge logic and edge cases

### Pipeline

- [x] `r2inspect/pipeline/analysis_pipeline.py` dependency resolution, skip logic, error handling
- [x] `r2inspect/pipeline/stages.py` hashing/detection/format stage behavior with stub analyzers

### Adapters

- [x] `r2inspect/adapters/validation.py` response validation and sanitization
- [x] `r2inspect/adapters/r2pipe_adapter.py` adapter behavior and command execution

### Registry and lazy loading

- [x] `r2inspect/registry/analyzer_registry.py` registration modes, metadata extraction, dependency order
- [x] `r2inspect/registry/default_registry.py` ensures expected analyzers registered
- [x] `r2inspect/lazy_loader.py` caching behavior, load failures, stats

### Schemas and conversions

- [x] `r2inspect/schemas/base.py` data validation behaviors
- [x] `r2inspect/schemas/format.py` format mapping rules
- [x] `r2inspect/schemas/metadata.py` metadata parsing
- [x] `r2inspect/schemas/security.py` score computation edge cases
- [x] `r2inspect/schemas/results.py` `from_dict` for minimal and full payloads
- [x] `r2inspect/schemas/converters.py` expected mapping behavior
- [x] `r2inspect/schemas/hashing.py` field normalization

### Utilities and helpers

- [x] `r2inspect/utils/r2_helpers.py` safe command wrappers
- [x] `r2inspect/utils/r2_suppress.py` suppression and fallback handling
- [x] `r2inspect/utils/hashing.py` deterministic hashing helpers
- [x] `r2inspect/utils/magic_detector.py` file type detection
- [x] `r2inspect/utils/output.py` CSV/JSON extraction helpers
- [x] `r2inspect/utils/retry_manager.py` retry policy and backoff
- [x] `r2inspect/utils/rate_limiter.py` limits enforced
- [x] `r2inspect/utils/circuit_breaker.py` open/close transitions
- [x] `r2inspect/utils/memory_manager.py` guardrails
- [x] `r2inspect/utils/error_handler.py` normalization paths
- [x] `r2inspect/utils/logger.py` configuration defaults

### Config

- [x] `r2inspect/config.py` defaults and overrides
- [x] `r2inspect/config_schemas/builder.py` schema building
- [x] `r2inspect/config_schemas/schemas.py` schema validation

### CLI (unit)

- [x] `r2inspect/cli/validators.py` input validation
- [x] `r2inspect/cli/analysis_runner.py` argument handling with stub pipeline
- [x] `r2inspect/cli/commands/*.py` command routing
- [x] `r2inspect/cli/display.py` formatting (minimal, deterministic checks)
- [x] `r2inspect/cli/batch_processing.py` batch inputs and error propagation
- [x] `r2inspect/cli/batch_output.py` output formats and edge cases
- [x] `r2inspect/cli_main.py` dispatch behavior

## Phase 2 - Module unit tests (mocked r2pipe)

Each analyzer should have unit tests that validate:

- correct handling of missing/empty r2 responses
- safe defaults when fields are absent
- deterministic outputs on provided fixtures

### PE/ELF/Mach-O format analyzers

- [x] `r2inspect/modules/pe_analyzer.py`
- [x] `r2inspect/modules/elf_analyzer.py`
- [x] `r2inspect/modules/macho_analyzer.py`

### PE adjunct analyzers

- [x] `r2inspect/modules/resource_analyzer.py`
- [x] `r2inspect/modules/rich_header_analyzer.py`
- [x] `r2inspect/modules/authenticode_analyzer.py`
- [x] `r2inspect/modules/import_analyzer.py`
- [x] `r2inspect/modules/export_analyzer.py`
- [x] `r2inspect/modules/section_analyzer.py`
- [x] `r2inspect/modules/overlay_analyzer.py`
- [x] `r2inspect/modules/exploit_mitigation_analyzer.py`

### Detection analyzers

- [x] `r2inspect/modules/packer_detector.py`
- [x] `r2inspect/modules/anti_analysis.py`
- [x] `r2inspect/modules/compiler_detector.py`
- [x] `r2inspect/modules/crypto_analyzer.py`
- [x] `r2inspect/modules/yara_analyzer.py` (mock yara hits)

## Phase X - Clean architecture pending analyzers (IO + heuristics mixed)

- [x] `r2inspect/modules/tlsh_analyzer.py`
- [x] `r2inspect/modules/binlex_analyzer.py`
- [x] `r2inspect/modules/simhash_analyzer.py`
- [x] `r2inspect/modules/bindiff_analyzer.py`
- [x] `r2inspect/modules/ccbhash_analyzer.py`
- [x] `r2inspect/modules/section_analyzer.py`
- [x] `r2inspect/modules/rich_header_analyzer.py`
- [x] `r2inspect/modules/elf_analyzer.py`
- [x] `r2inspect/modules/string_analyzer.py`
- [x] `r2inspect/modules/macho_analyzer.py`
- [x] `r2inspect/modules/pe_resources.py`
- [x] `r2inspect/modules/function_analyzer.py`
- [x] `r2inspect/modules/overlay_analyzer.py`
- [x] `r2inspect/modules/export_analyzer.py`
- [x] `r2inspect/modules/compiler_detector.py`
- [x] `r2inspect/modules/elf_security.py`
- [x] `r2inspect/modules/authenticode_analyzer.py`
- [x] `r2inspect/modules/impfuzzy_analyzer.py`
- [x] `r2inspect/modules/anti_analysis.py`
- [x] `r2inspect/modules/exploit_mitigation_analyzer.py`
- [x] `r2inspect/modules/pe_imports.py`
- [x] `r2inspect/modules/binbloom_analyzer.py`
- [x] `r2inspect/modules/resource_analyzer.py`
- [x] `r2inspect/modules/import_analyzer.py`
- [x] `r2inspect/modules/packer_detector.py`
- [x] `r2inspect/modules/telfhash_analyzer.py`
- [x] `r2inspect/modules/pe_security.py`
- [x] `r2inspect/modules/yara_analyzer.py`

## Phase X+ - Clean architecture (conceptual) hardening

### Qué aún rompe “estricta” (conceptual)

- [x] Separación dominio/IO en analyzers: mover lógica a domain services y dejar analyzers como orquestadores.
- [x] Core sin infraestructura: sacar creación/inyectado de backends fuera del core y depender solo de interfaces.

### Posibles mejoras adicionales (sin perder funcionalidad)

- [x] Extraer más lógica pura a helpers de dominio en analyzers complejos (strings/heurísticas).
- [x] Unificar patrones repetidos (search/entropy/scoring) en helpers comunes si aparece duplicación.
- [x] Recortar docstrings largos restantes en módulos verbosos.

### Plan concreto (archivos y pasos)

#### Fase A — Separación dominio/IO por áreas (sin romper API)

- [x] `r2inspect/modules/*_analyzer.py`: identificar IO directo restante (`execute_command`, `_cmd*`) y mover parseo/heurísticas a `r2inspect/modules/*_domain.py`.
- [x] `r2inspect/modules/elf_analyzer.py`: mover `_read_section`, `_find_section` a `elf_domain.py` como funciones puras (input: secciones/bytes/strings).
- [x] `r2inspect/modules/macho_analyzer.py`: mover construcción de `sections`/`load_commands` a `macho_domain.py`.
- [x] `r2inspect/modules/pe_analyzer.py`: mover postprocesado de `resource_info`/`version_info` a `pe_info_domain.py`.
- [x] `r2inspect/modules/import_analyzer.py`: mover `_find_suspicious_patterns`/`_assess_api_risk` a `import_domain.py`.
- [x] `r2inspect/modules/anti_analysis.py`: mover patrones/heurísticas a `anti_analysis_domain.py` (input: listas/strings ya extraídas).

#### Fase B — Backend/Adapter rico (menos comandos crudos)

- [x] `r2inspect/interfaces/binary_analyzer.py`: añadir métodos de alto nivel (ej. `get_strings`, `get_functions`, `get_disasm`, `get_cfg`).
- [x] `r2inspect/adapters/r2pipe_adapter.py`: implementar esos métodos con caching.
- [x] `r2inspect/modules/*_analyzer.py`: sustituir `execute_command`/`_cmd*` por métodos de adapter cuando existan.

#### Fase C — Core sin infraestructura

- [x] `r2inspect/core/factory.py`: mover toda creación de adapter/registry/pipeline_builder aquí (ya existe; consolidar uso).
- [x] `r2inspect/core/inspector.py`: depender solo de interfaces y objetos ya inyectados (sin construir nada).
- [x] `r2inspect/cli/*`: usar `create_inspector()` para construir desde CLI y eliminar rutas de compat en core.

#### Fase D — Helpers compartidos y deduplicación

- [x] `r2inspect/modules/search_helpers.py`: centralizar TODO search (`/c`, `/x`) y usar desde analyzers.
- [x] `r2inspect/modules/domain_helpers.py`: consolidar entropy/scoring utilidades duplicadas.
- [x] `r2inspect/modules/*_domain.py`: revisar duplicaciones de parseo (strings, imports, sections) y unificar.

#### Fase E — Limpieza final

- [x] `r2inspect/modules/*.py`: recortar docstrings largos restantes (mantener intención, eliminar redundancias).
- [x] `r2inspect/config_schemas/*.py`: compactar docstrings y comentarios largos que ya no aportan.

#### Fase F — Calidad extra (opcional)

- [x] Convenciones/estilo: normalizar naming, estructura de módulos y consistencia de logging.
  - [x] Unificar prefijos y nombres de métodos (`_cmd/_cmdj/_cmd_list` vs `execute_command`).
  - [x] Alinear nombres de resultados (`results`, `result`, `analysis`) y claves de salida entre analyzers.
  - [x] Normalizar mensajes de logging (niveles y formato) en `modules/` y `core/`.
- [x] Tipos: reforzar typing en interfaces y adapters.
  - [x] `r2inspect/interfaces/*`: añadir Protocols más específicos (retornos concretos).
  - [x] `r2inspect/adapters/r2pipe_adapter.py`: tipar cachés, helpers y `execute_command` con `Literal`/`TypedDict` cuando aplique.
  - [x] Analyzers: tipar retornos y estructuras clave con `TypedDict` (solo donde aporta claridad).
- [x] Documentación técnica: actualizar docs internas a la nueva arquitectura.
  - [x] `README.md` y `docs/*`: reflejar `create_inspector` + DI + adapter.
  - [x] Añadir diagrama simple de capas (core/domain/adapters/cli).

### Hashing/similarity analyzers

- [x] `r2inspect/modules/ssdeep_analyzer.py`
- [x] `r2inspect/modules/tlsh_analyzer.py`
- [x] `r2inspect/modules/telfhash_analyzer.py`
- [x] `r2inspect/modules/impfuzzy_analyzer.py`
- [x] `r2inspect/modules/ccbhash_analyzer.py`
- [x] `r2inspect/modules/simhash_analyzer.py`
- [x] `r2inspect/modules/binlex_analyzer.py`
- [x] `r2inspect/modules/binbloom_analyzer.py`
- [x] `r2inspect/modules/bindiff_analyzer.py`
- [x] `r2inspect/modules/string_analyzer.py`
- [x] `r2inspect/modules/function_analyzer.py`

## Phase 3 - Integration tests (real r2pipe + fixtures)

### Fixture set

- [x] Curate minimal sample binaries for PE/ELF/Mach-O (safe, non-malicious)
- [x] Add fixtures for edge cases: packed sample, high entropy, missing headers, tiny files
- [x] Add expected output JSON per fixture

### Integration suites

- [x] Analyze each fixture end-to-end via `R2Inspector` and compare to golden output
- [x] Validate pipeline dependency resolution with optional analyzers toggled
- [x] Validate config-driven behavior (disable analyzers, set timeouts)
- [x] Validate lazy-loader impact on loaded analyzers count

## Phase 4 - CLI and UX tests

- [x] `r2inspect` CLI smoke tests (help, version, config show)
- [x] `analyze` command on fixture, validate output files
- [x] `batch` command on a directory, verify per-file results
- [x] Verify interactive mode minimal flows

## Phase 5 - Security, resilience, and error handling

- [x] Bandit-aligned negative tests (timeouts, invalid inputs, missing deps)
- [x] Ensure safe failure on missing optional libs (yara, ssdeep, tlsh, pybloom)
- [x] Regression tests for previous parsing bugs
- [x] Deserialization safety test for binbloom JSON input

## Phase 6 - Performance and resource usage

- [x] Benchmarks guarded by `slow` marker
- [x] Import-time and registry-creation baselines
- [x] Memory usage baseline and regression thresholds
- [x] Lazy loading effectiveness metrics

## Phase 7 - Coverage completion

- [x] Add coverage reporting in CI (`pytest --cov=r2inspect`)
- [x] Enforce minimum coverage target (start at 60%, raise to 80%+)
- [x] Add mutation tests for critical components (optional)

## Acceptance criteria for “complete coverage”

- [x] All modules covered by unit tests
- [x] All analyzers covered by integration fixtures
- [x] CLI workflows validated
- [x] Critical failure paths validated
- [x] Coverage target met and stable in CI

## Phase 36 - Clean architecture strictness (remaining)

### A. Adapter purity (remove direct r2/safe_cmd in analyzers)

- [x] `r2inspect/modules/bindiff_analyzer.py`: replace direct `r2.cmd*`/`safe_cmd*` with adapter high-level methods (`get_functions`, `get_strings`, `get_cfg`, `get_disasm`, `read_bytes`).
- [x] `r2inspect/modules/tlsh_analyzer.py`: replace `safe_cmd*` uses for sections/functions/bytes with adapter methods.
- [x] `r2inspect/modules/rich_header_analyzer.py`: replace direct `r2.cmd` seek/read with adapter helpers or new adapter methods.
- [x] `r2inspect/modules/compiler_detector.py`: replace direct `r2.cmd/cmdj` uses with adapter methods (`get_strings`, `get_imports`, `get_sections`, `get_symbols`).
- [x] `r2inspect/modules/function_analyzer.py`: replace direct `cmd/cmdj` usage with adapter disasm/CFG helpers.
- [x] `r2inspect/modules/section_analyzer.py`: replace inline `/c` search and raw cmd access with adapter search helpers.
- [x] `r2inspect/modules/simhash_analyzer.py`: replace direct `cmd/cmdj` usage with adapter disasm/strings helpers.
- [x] `r2inspect/modules/pe_resources.py`: replace raw `_cmd/_cmdj` with adapter helpers.
- [x] `r2inspect/modules/pe_security.py`: replace raw `_cmd` with adapter helpers.
- [x] `r2inspect/modules/elf_security.py`: replace raw `_cmd` with adapter helpers.

### B. Interface purity (remove generic execute_command escape hatches)

- [x] `r2inspect/interfaces/binary_analyzer.py`: remove or deprecate `execute_command` from the protocol to force high-level access only.
- [x] `r2inspect/modules/*`: remove any fallback to `execute_command` for analyzers that can use adapter methods.

### C. Core isolation (move r2 session outside core)

- [x] `r2inspect/core/r2_session.py`: move r2pipe lifecycle into adapters/infrastructure layer; core should only depend on an interface.
- [x] `r2inspect/core/inspector.py`: remove any direct r2 session knowledge (construct via DI only).

### D. Domain extraction (final)

- [x] `r2inspect/modules/rich_header_analyzer.py`: extract remaining pure parsing into `rich_header_domain.py`.
- [x] `r2inspect/modules/bindiff_analyzer.py`: extract similarity/scoring helpers into `bindiff_domain.py` and remove inline scoring math.

### E. Clean code consistency sweep

- [x] Normalize remaining `_cmd/_cmdj` wrappers to shared helpers where needed.
- [x] Trim any remaining long docstrings in large modules (rich_header, bindiff, simhash).
