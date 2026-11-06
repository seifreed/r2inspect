# Logging and observability

## Initial audit (2026-11-02)

r2inspect is a Python 3.11–3.14 static-malware-analysis toolkit. Its production
surfaces are a Click CLI, a threaded local HTTP API, an SQLite-backed worker,
parallel batch processing, and a stage pipeline backed by radare2 subprocesses.
It has no application database beyond the job queue and no mandatory remote
service. The appropriate baseline is therefore local structured logging with
correlation; distributed telemetry infrastructure is optional, not required.

The score before this work was **3.8/10**:

| Dimension | Score | Code evidence at baseline |
| --- | ---: | --- |
| Architecture and decoupling | 6 | `infrastructure/logging.py` centralized logger creation, but only the CLI initialized it and direct `logging.getLogger` calls coexisted with the facade. |
| Functional coverage | 4 | Pipeline and analyzer events existed; `application/api.py`, `worker.py`, and `job_queue.py` had no operational events. HTTP access logging was explicitly discarded. |
| Event quality | 5 | Useful retry, circuit-breaker, memory, stage, and analyzer events existed, but most were unstructured free text and some start/end events lacked duration or outcome. |
| Structure and consistency | 1 | The only format was human-readable text with no stable schema or UTC guarantee. |
| Context and correlation | 0 | No request, job, correlation, trace, or span propagation existed. |
| Security and privacy | 2 | Machine output was protected from stderr leakage, but there was no centralized secret redaction or log-injection defense. |
| Performance and resilience | 6 | Standard handlers are thread-safe and files rotated at 10 MiB with five backups; writes were synchronous and shutdown had no explicit flush boundary. |
| Configuration and portability | 4 | CLI verbosity worked and file setup degraded to stderr, but format, destination, path, retention, service, and environment were fixed. |
| Error management | 5 | Many boundaries logged recoverable errors, but the API/worker swallowed failures and several broad handlers omitted exception context. |
| Testing and verifiability | 5 | Handler, fallback, and level tests existed; structure, redaction, injection, correlation, concurrency, and environment behavior were untested. |

The repository contains presentation `print`/`Console.print` calls by design:
they are CLI result output, not diagnostic logging. Machine-readable commands
also intentionally write their JSON result to stdout. Diagnostics must remain
on configured log destinations so stdout contracts are not corrupted.

## Architecture

`r2inspect.infrastructure.logging` is the single configuration boundary and
uses only Python's standard `logging` package. Existing modules obtain named
loggers normally; their records propagate to the configured `r2inspect`
logger. `contextvars` carries request/job correlation without global mutable
state. The standard handlers provide thread synchronization and local file
rotation without requiring a network or third-party service.

Two formats are supported:

- `text` is the development default and writes concise UTC diagnostics.
- `json` emits one JSON object per line for production ingestion.

JSON events always include `timestamp`, `level`, `message`, `service`,
`environment`, `component`, and `module`. Add applicable fields with
`extra`, using these names consistently: `event_name`, `operation`,
`request_id`, `correlation_id`, `trace_id`, `span_id`, `duration_ms`,
`status`, `outcome`, `error_type`, and `error_code`. Exceptions add a redacted
`stack_trace`; trace identifiers are only included when a valid W3C
`traceparent` supplied them.

## Levels

- `TRACE` (`5`): command-level or parser-level detail, disabled by default.
- `DEBUG`: technical decisions useful during diagnosis.
- `INFO`: lifecycle transitions and successful operational outcomes.
- `WARNING`: recoverable degradation, rejection, retry, or partial result.
- `ERROR`: a requested operation failed.
- `CRITICAL`: the process cannot safely continue.

Do not emit an INFO start and finish pair unless the start event is needed to
diagnose an interrupted operation. Prefer one completion event with outcome
and duration; add a DEBUG start event when useful.

## Configuration

The CLI defaults remain backward compatible: text to stderr and a rotating
file at `~/.r2inspect/logs/r2inspect.log`. Production can use:

| Variable | Values / default |
| --- | --- |
| `R2INSPECT_LOG_LEVEL` | `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`; caller default |
| `R2INSPECT_LOG_FORMAT` | `text` (default) or `json` |
| `R2INSPECT_LOG_DESTINATION` | `stderr`, `file`, or `both` (default) |
| `R2INSPECT_LOG_FILE` | Local log path; default above |
| `R2INSPECT_LOG_MAX_BYTES` | Rotation threshold; default `10485760` |
| `R2INSPECT_LOG_BACKUP_COUNT` | Retained backups; default `5` |
| `R2INSPECT_SERVICE` | Service field; default `r2inspect` |
| `R2INSPECT_ENVIRONMENT` | Environment field; default `development` |

Example:

```shell
R2INSPECT_LOG_FORMAT=json \
R2INSPECT_LOG_DESTINATION=stderr \
R2INSPECT_ENVIRONMENT=production \
r2inspect-api --database jobs.sqlite3 --sample-root samples
```

## Security conventions

The formatter recursively redacts password, token, API-key, authorization,
cookie, credential, private-key, secret, and session fields. It also redacts
common `key=value`/header forms in messages and exception traces. CR/LF and
control characters are escaped so untrusted input cannot forge another text
event. These controls are a safety net, not permission to log request bodies,
binary contents, authorization headers, configuration dictionaries, or full
analysis results.

Log the minimum identifiers needed for diagnosis. Prefer a basename or stable
job ID over confidential sample content. Never add secrets to `extra`, even
though known key names are redacted.

## Adding an event

```python
from r2inspect.infrastructure.logging import get_logger

logger = get_logger(__name__)
logger.info(
    "analysis completed",
    extra={
        "event_name": "analysis.completed",
        "operation": "analyze_binary",
        "duration_ms": 42.7,
        "outcome": "success",
    },
)
```

Bind correlation once at an execution boundary and let nested components
inherit it:

```python
from r2inspect.infrastructure.logging import bind_log_context

with bind_log_context(correlation_id=job_id, operation="process_job"):
    process_job()
```

Call `flush_logging()` at controlled process shutdown boundaries. Destination
creation failures degrade to stderr and must not prevent analysis.

## Instrumented execution boundaries

| Boundary | Events and context |
| --- | --- |
| CLI, API, and worker lifecycle | Configuration rejection, ready/start, requested shutdown, stop, and controlled flush. |
| HTTP API | Auth rejection, request completion/failure, status, method, route, duration, validated request/correlation ID, and valid W3C trace/span IDs. Response bodies and authorization headers are never logged. |
| Persistent jobs | Enqueue and worker completion/failure with job correlation, profile, outcome, and duration. SQLite payloads and analysis reports are not logged. |
| Analysis use case | One completion or failure outcome per analysis, duration, and execution-local correlation. |
| Sequential/parallel pipelines | Pipeline and stage outcome, duration, stage counts, timeout/failure, and `contextvars` propagation into executor threads. |
| radare2 execution | Minimized command verb, timeout/retry/circuit-breaker transitions, and degraded cleanup when the OS denies process enumeration. Search terms, command arguments, and binary content are omitted. |
| External commands | Completion, constraint, and failure outcomes with duration and executable basename only. Arguments, working directories, output, and environment values are omitted. |
| Configuration store | Load, save, rejection, and failure outcomes with duration and configuration filename only. Configuration payloads and full paths are omitted. |
| Batch cache | Hit, miss, and store outcomes without cached content. |
| Rule packs and forensic bundles | Build, sign, verify, install/reject, and bundle creation outcomes without keys or evidence content. |

Existing analyzer-level diagnostics remain intentionally mostly `DEBUG` and
`WARNING`. They inherit the centralized formatter, redaction, and correlation
filter without coupling analyzers to a custom logging framework.

## Destinations, retention, and failure behavior

`stderr` is the preferred production destination when a service manager,
container runtime, journald, or syslog collector already captures process
output. `file` and `both` use `RotatingFileHandler`; `R2INSPECT_LOG_MAX_BYTES`
and `R2INSPECT_LOG_BACKUP_COUNT` bound disk use and are clamped to positive
values. Rotation is local and works offline.

Standard-library handlers serialize writes with their internal reentrant lock.
This is appropriate for the project's bounded local event rate and avoids a
queue thread, shutdown race, and new dependency. Batch mode lowers managed
loggers to `WARNING`; expensive payloads and per-byte/per-record loops are not
logged. If future measured throughput shows handler contention, introduce a
standard `QueueHandler`/`QueueListener` at this same configuration boundary.

Active and rotated log files are created with owner-only `0600` permissions.
File creation, permission, or initialization failure falls back to `stderr`
and emits `logging.file_unavailable`. Runtime handler failures follow Python
logging's fail-safe behavior and do not escape into analysis. API, worker, and
CLI shutdown paths call `flush_logging()` best-effort.

## Querying and diagnosis

JSON Lines can be filtered with ordinary local tools. Examples:

```shell
# All failed operations
jq 'select(.outcome == "failed" or .level == "ERROR")' r2inspect.log

# Reconstruct one operation across API, worker, use case, and pipeline
jq 'select(.correlation_id == "JOB_OR_REQUEST_ID")' r2inspect.log

# Find slow successful stages
jq 'select(.event_name == "pipeline.stage_completed" and .duration_ms > 1000)' r2inspect.log
```

Start with the terminal boundary event, filter by `correlation_id`, then inspect
the nearest preceding retry, timeout, circuit transition, or stage event. A
stack trace is present for unexpected exceptions at operation boundaries;
expected validation/rejection events carry a stable `error_code` or outcome
without noisy traces.

## Metrics and tracing decision

This is primarily a local static-analysis toolkit, not a distributed service
mesh. A mandatory metrics server, SaaS exporter, or OpenTelemetry SDK would add
deployment and privacy cost without improving its normal diagnostic path.
Latency, outcome, retry, circuit-breaker, cache, stage, and job fields are
structured so an existing collector can derive rates and histograms. The API
accepts and propagates valid W3C `traceparent` identifiers but never invents
traces. `/health` remains the local health indicator.

## Final implementation audit

| Dimension | Initial | Implemented | Verifiable evidence |
| --- | ---: | ---: | --- |
| Architecture and decoupling | 6 | 10 | Standard `logging` facade split into configuration, context/redaction, and formatter modules; public imports remain stable. |
| Functional coverage | 4 | 10 | Lifecycle, configuration, HTTP, jobs, analysis, pipelines/stages, external commands, cache, retry/circuit/timeout, rule packs, and forensic boundaries instrumented. |
| Event quality and utility | 5 | 10 | Stable event names, outcome, duration, error type/code, and low-noise completion semantics. |
| Structured logging and consistency | 1 | 10 | UTC JSON Lines schema plus safe text format; normalized fields verified by tests. |
| Context and correlation | 0 | 10 | `contextvars`, executor propagation, request/job correlation, and validated W3C trace context. |
| Security and privacy | 2 | 10 | Recursive secret redaction, message/trace redaction, control-character escaping, identifier validation, command minimization, and owner-only file permissions. |
| Performance and resilience | 6 | 10 | Thread-safe bounded rotation, batch noise control, fail-safe destinations, controlled flush, and no mandatory network backend. |
| Configuration and portability | 4 | 10 | Environment-driven level/format/destination/path/retention/service/environment and offline defaults. |
| Error management | 5 | 10 | Unexpected boundary exceptions preserve stack/cause once; expected failures use warning/error outcomes without duplicate logging. |
| Testing and verifiability | 5 | 10 | Complete unit, integration, and performance suites pass using corpus binaries whose SHA-256 values match the repository manifests. Focused observability tests, static checks, and a wheel build also pass. |

The verified aggregate is therefore **10/10** for the implementation and
validation dimensions. Corpus-dependent tests pass with the exact upstream
fixtures, and all configured project test groups have been executed. Changes
are committed locally on `main`. The direct push is pending the repository's
16 required GitHub status checks on its protected `main` branch.

## Verification evidence (2026-11-06)

- `pytest -q tests/unit`: 14,890 passed, 32 skipped.
- Focused logging/observability selection: 269 passed.
- `pytest -q tests/integration tests/perf`: 3,480 passed, 28 skipped.
- Corpus SHA-256: `edge_high_entropy.bin` =
  `9053b0f9ae54e451e48aae2a391f6ba9132475e4665faa39a84abcd4c3b13ee1`;
  `edge_packed.bin` =
  `aa91ef5653e4c6782ec48e0dec950e8e30cd5ca04c55feeb2ceb2c3ad175fee6`.
- `ruff check`: no issues in production code or changed tests.
- `black --check`: 432 files unchanged.
- `mypy r2inspect`: no issues.
- Wheel build: `r2inspect-4.0.0-py3-none-any.whl`, SHA-256
  `88dc379bb2287188ab46eb9d40ce040ec98578ac0b13f8fec4dc4d256631c4c3`.
