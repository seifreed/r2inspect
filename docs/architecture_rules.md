# Architecture Rules

This document defines the target architecture for `r2inspect` and the rules new
code should follow.

## Layers

### `domain/`

- Contains business rules, scoring, signatures, grouping, policies, and value objects.
- Must be pure Python logic whenever possible.
- Must not import from `cli`, `adapters`, `infrastructure`, or `utils`.

### `application/`

- Contains use cases and orchestration.
- May depend on `domain` and `interfaces`.
- Must not depend on `cli`.
- Must interact with environment/runtime concerns through ports.

### `interfaces/`

- Defines ports and protocols shared across layers.
- Must not contain concrete behavior tied to specific tools.

### `adapters/`

- Implements ports for radare2, libmagic, filesystem, schema validation, runtime stats, and similar edge concerns.
- May depend on `interfaces`, `domain`, and external libraries.
- Must not contain business decision logic that belongs in `domain`.

### `pipeline/`

- Composes and executes stages.
- May depend on `interfaces`, `application`, and `domain`.
- Must not instantiate infrastructure directly.

### `cli/`

- Handles input parsing, output formatting, and process lifecycle.
- Must not own business rules.
- May call `application` use cases and presentation helpers.

## Dependency Rules

Allowed direction:

`cli -> application -> domain`

`cli -> adapters`

`pipeline -> interfaces/application/domain`

`adapters -> interfaces/domain`

Forbidden direction:

- `domain -> application`
- `domain -> adapters`
- `domain -> cli`
- `application -> cli`
- `pipeline -> adapters` when a port can be injected instead

## Analyzer Rules

- Analyzers are adapters around domain logic.
- An analyzer may:
  - fetch raw data from backend adapters
  - normalize backend payloads
  - call domain services
  - map domain output to result schema
- An analyzer should not:
  - embed complex scoring rules
  - own similarity/grouping logic
  - mix extraction, heuristics, scoring, and formatting in one large method

## `utils/` Migration Rules

`utils/` is transitional. New shared logic should be placed in the correct layer:

- Domain logic -> `domain/`
- Environment/tool access -> `adapters/` or `infrastructure/`
- Use-case helpers -> `application/`
- Presentation helpers -> `cli/`

## Done Criteria For A Refactor

A component is considered aligned when:

- infrastructure access is isolated behind a port or adapter
- business rules are exercised without CLI or radare2
- the public entrypoint is smaller after the refactor
- tests target behavior at the domain/use-case boundary, not private helper trivia

## Guardrails

The test suite enforces a first structural quality floor:

- `domain/` must stay small and pure: max 360 lines per file, max 45 lines per function
- `application/` must stay orchestration-focused: max 180 lines per file, max 95 lines per function
- `pipeline/` should stay compositional: max 360 lines per file, max 75 lines per function
Temporary exceptions are allowed only when listed explicitly in the architecture tests.
