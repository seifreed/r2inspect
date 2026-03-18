# Architecture Overview

r2inspect is structured around use cases, a small core orchestrator, and pluggable adapters.

Key ideas:

- Core logic is in `R2Inspector` and the analysis pipeline; it depends on ports and injected providers instead of concrete infrastructure helpers.
- Application use cases orchestrate analysis and batch execution and return pure results; CLI modules handle presentation and file output.
- Adapters provide backend and environment access (e.g. r2pipe/radare2, libmagic, schema validation/runtime statistics).
- Domain models capture analysis result shapes and batch execution outcomes.
- `cli/batch_processing.py` is now a facade over smaller batch runtime/path/presentation helpers.
- Compatibility shims are no longer part of the package; runtime code and tests use canonical imports directly.

```
CLI -> use cases -> create_inspector -> R2Inspector -> AnalysisPipeline -> analyzers
                                    -> Adapters (r2pipe/libmagic/runtime) -> external tools
```

See `docs/architecture_rules.md` for the dependency rules that new refactors
must follow.

If you need a custom backend, implement the adapter interface and pass it into
the inspector factory.
