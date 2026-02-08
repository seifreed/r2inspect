# Architecture Overview

r2inspect is structured around a small core orchestrator and pluggable adapters.

Key ideas:

- Core logic is in `R2Inspector` and the analysis pipeline; it only depends on interfaces.
- Adapters provide backend data access (e.g. r2pipe/radare2).
- Analyzers focus on analysis and delegate pure heuristics to domain helpers where possible.

```
CLI -> create_inspector -> R2Inspector -> AnalysisPipeline -> analyzers
                                      -> Adapter (r2pipe) -> radare2
```

If you need a custom backend, implement the adapter interface and pass it into
the inspector factory.
