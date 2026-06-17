"""Pytest configuration for shared fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    import resource as _resource
except ImportError:
    _resource = None  # type: ignore[assignment]

import pytest

from r2inspect.testing.fixtures import (
    ensure_expected_snapshots,
    resolve_fixture_source_root,
    sync_sample_fixtures,
)
from tests.helpers.process_reaper import reap_process

# =============================================================================
# Test Resource Limits Configuration
# =============================================================================
# These defaults are aggressive to prevent tests from overwhelming the machine.
# Override via environment variables if needed.

DEFAULT_TEST_MAX_WORKERS = "1"  # Single worker to reduce r2 process spawning
DEFAULT_TEST_MAX_THREADS = "1"  # Single thread for r2 operations
DEFAULT_TEST_MEMORY_LIMIT_MB = 1024  # 1GB memory limit per test process
DEFAULT_TEST_CPU_LIMIT_SECONDS = 300  # 5 minute CPU time limit per test session


@pytest.fixture(scope="session")
def _session_samples_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the shared sample-fixture tree used by session-scoped test helpers."""
    repo_root = Path(__file__).resolve().parent.parent
    source_root = resolve_fixture_source_root(repo_root)
    if source_root is None:
        pytest.skip(
            "No fixture binaries found. Set R2INSPECT_TEST_BINARIES_DIR or clone "
            "../r2inspect-test-binaries."
        )

    if (source_root / "hello_pe.exe").exists():
        ensure_expected_snapshots(source_root)
        return source_root

    fixture_dir = tmp_path_factory.mktemp("sample_fixtures")
    sync_sample_fixtures(fixture_dir, source_root)
    return fixture_dir


@pytest.fixture(scope="session")
def samples_dir(_session_samples_dir: Path) -> Path:
    """Return the shared sample-fixture directory backed by the binaries repo."""
    return _session_samples_dir


@pytest.fixture(autouse=True, scope="session")
def cap_test_resources(tmp_path_factory: pytest.TempPathFactory) -> None:
    """
    Apply aggressive resource caps during tests to avoid overloading the machine.

    r2inspect test mode enables:
      - Single worker/thread execution (no parallel r2 sessions)
      - Lightweight analysis mode (skips heavy aaa analysis)
      - Disabled r2 plugins to reduce overhead
      - Memory and CPU limits to prevent runaway processes
      - A neutral radare2rc so analysis never inherits the developer's
        ~/.radare2rc (an rc with ``e cfg.debug=true`` makes radare2
        debug-launch the sample on open, hanging r2pipe). Production code
        already passes ``-N``; this covers tests that call ``r2pipe.open``
        directly and keeps the suite deterministic across machines/CI.

    Caps are configurable via env vars:
      - R2INSPECT_MAX_WORKERS (defaults to 1 in test mode)
      - R2INSPECT_MAX_THREADS (defaults to 1 in test mode)
      - R2INSPECT_DISABLE_PLUGINS (defaults to 1)
      - R2INSPECT_TEST_MODE (defaults to 1, enables lightweight analysis)
      - R2INSPECT_TEST_MAX_CPU_SECONDS (defaults to 300)
      - R2INSPECT_TEST_MAX_AS_MB (defaults to 1024)
      - R2INSPECT_ANALYSIS_DEPTH (defaults to 1 in test mode, use aa not aaa)
      - R2_RCFILE (defaults to an empty session rc; radare2 loads this
        instead of ~/.radare2rc)
    """
    if "R2_RCFILE" not in os.environ:
        neutral_rc = tmp_path_factory.mktemp("r2rc") / "radare2rc"
        neutral_rc.write_text("")
        os.environ["R2_RCFILE"] = str(neutral_rc)

    if os.getenv("COV_CORE_SOURCE") and not os.getenv("COVERAGE_PROCESS_START"):
        config_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        os.environ["COVERAGE_PROCESS_START"] = str(config_path)

    # Enable test mode - this triggers lightweight analysis in R2Session
    os.environ.setdefault("R2INSPECT_TEST_MODE", "1")

    # Disable forced exit timer so batch tests don't kill the pytest process
    os.environ.setdefault("R2INSPECT_DISABLE_FORCED_EXIT", "1")

    # Limit parallelism to prevent multiple r2 processes from spawning
    os.environ.setdefault("R2INSPECT_MAX_WORKERS", DEFAULT_TEST_MAX_WORKERS)
    os.environ.setdefault("R2INSPECT_MAX_THREADS", DEFAULT_TEST_MAX_THREADS)

    # Disable r2 plugins to reduce memory overhead
    os.environ.setdefault("R2INSPECT_DISABLE_PLUGINS", "1")

    # Bound telfhash quickly in tests: telfhash 0.9.8 infinite-loops on
    # PT_LOAD-less ELFs, so fixtures that exercise that path must fail fast
    # instead of taking the 30s production timeout.
    os.environ.setdefault("R2INSPECT_TELFHASH_TIMEOUT_SECONDS", "3")

    # Use shallow analysis depth (aa instead of aaa)
    os.environ.setdefault("R2INSPECT_ANALYSIS_DEPTH", "1")

    # Apply default memory limit unless overridden
    cpu_limit = os.getenv("R2INSPECT_TEST_MAX_CPU_SECONDS", "").strip()
    as_limit = os.getenv("R2INSPECT_TEST_MAX_AS_MB", "").strip()

    # Set default CPU limit if not specified
    if not cpu_limit:
        cpu_limit = str(DEFAULT_TEST_CPU_LIMIT_SECONDS)

    # Set default memory limit if not specified
    if not as_limit:
        as_limit = str(DEFAULT_TEST_MEMORY_LIMIT_MB)

    # Apply CPU time limit
    if cpu_limit and _resource is not None:
        try:
            seconds = int(cpu_limit)
            if seconds > 0:
                _resource.setrlimit(_resource.RLIMIT_CPU, (seconds, seconds))
        except (ValueError, OSError):
            pass

    # Apply memory (address space) limit
    if as_limit and _resource is not None:
        try:
            mb = int(as_limit)
            if mb > 0:
                bytes_limit = mb * 1024 * 1024
                # RLIMIT_AS may not be available on all platforms
                if hasattr(_resource, "RLIMIT_AS"):
                    _resource.setrlimit(_resource.RLIMIT_AS, (bytes_limit, bytes_limit))
        except (ValueError, OSError):
            pass


@pytest.fixture(autouse=True, scope="session")
def ensure_sample_fixture_tree(_session_samples_dir: Path) -> None:
    """
    Ensure samples/fixtures paths exist for tests with hardcoded repository paths.

    The project keeps binaries in an external fixture repo; this recreates the
    local samples tree as symlinks (or copies) during test execution only.
    """
    repo_root = Path(__file__).resolve().parent.parent
    sample_fixtures = repo_root / "samples" / "fixtures"
    created = False
    created_files: list[Path] = []

    if not sample_fixtures.exists():
        sample_fixtures.mkdir(parents=True, exist_ok=True)
        created = True

    for source in _session_samples_dir.iterdir():
        target = sample_fixtures / source.name
        if target.exists():
            continue
        # `target.exists()` returns False for a dangling symlink (the link itself
        # is present but its destination is gone — e.g. a stale pytest tmpdir from
        # a previous run). Remove it so `symlink_to` below doesn't FileExistsError.
        if target.is_symlink():
            target.unlink(missing_ok=True)
        try:
            target.symlink_to(source)
        except FileExistsError:
            # A parallel pytest-xdist worker created it first; nothing to do.
            continue
        except OSError:
            if not target.exists():
                target.write_bytes(source.read_bytes())
        created_files.append(target)

    yield

    # Under pytest-xdist the per-worker sessions overlap: a worker that finishes
    # first must NOT tear down the shared tree while slower workers are still
    # running, or their tests lose the fixtures mid-run. The binaries are
    # gitignored and regenerated on the next run, so leaving them is harmless.
    if os.environ.get("PYTEST_XDIST_WORKER") is not None:
        return

    for target in created_files:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass

    if created:
        try:
            sample_fixtures.rmdir()
            sample_fixtures.parent.rmdir()
        except OSError:
            pass


@pytest.fixture(autouse=True, scope="module")
def cleanup_r2_processes():
    """Reap orphaned radare2 child processes once per test module.

    The R2 session closes radare2 via ``r2.quit()`` on ``close()`` (see
    ``infrastructure/r2_session.py``), so well-behaved tests leak nothing; this
    is a belt-and-suspenders sweep for a test that spawns r2 and dies before
    closing. Module scope (not per-function) keeps the sweep regular while
    avoiding ~9 minutes of redundant full-suite overhead: a whole-system
    ``psutil.process_iter`` scan costs ~40ms and per-test it ran 13k+ times.

    Only our own descendant radare2 processes are terminated. Scanning the
    current process subtree is cheaper than a whole-system scan and avoids
    killing an unrelated radare2 the developer may be running elsewhere.
    """
    yield
    if sys.platform == "win32":
        return
    try:
        import psutil

        try:
            children = psutil.Process().children(recursive=True)
        except psutil.NoSuchProcess:
            return
        for proc in children:
            try:
                if "radare2" in (proc.name() or "").lower():
                    reap_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        pass


@pytest.fixture(autouse=True)
def _reset_global_state():
    """Auto-reset shared singletons and global state between tests.

    Several process-global caches are mutated by tests without restoration
    and poison later, ordering-dependent runs:

    - ``configure_batch_logging()`` lowers the six ``r2inspect.*`` logger
      levels to WARNING; many callers never call ``reset_logging_levels()``,
      breaking later ``caplog.at_level(DEBUG)`` tests.
    - ``ssdeep_loader._ssdeep_module`` is a lazy module cache tests swap to
      fakes/``None``.
    - ``ResultConverterImpl._schema_registry`` is a class dict tests
      ``.clear()``, wiping the import-time default schemas process-wide.
    - ``batch_discovery_runtime.magic`` / ``batch_processing.magic`` are
      module globals tests reassign (to ``None``/fakes) without restoring.
    - ``sys.modules['ssdeep']`` is left holding a fake by tests that inject
      one on ``sys.path`` and only clean up the path.

    - The current working directory: several tests ``os.chdir(tmp_path)``
      without restoring it, so later tests resolving relative paths (e.g.
      ``samples/fixtures/hello_pe.exe``) fail once that tmp dir is removed.

    Snapshot before / restore after makes all of these ordering-independent.
    Restoring only ever re-applies the pre-test value, so a correct test's
    outcome cannot change.
    """
    import logging as _logging
    import os as _os

    try:
        _saved_cwd: str | None = _os.getcwd()
    except OSError:
        _saved_cwd = None

    _logger_names = (
        "r2inspect",
        "r2inspect.core",
        "r2inspect.pipeline",
        "r2inspect.modules",
        "r2inspect.infrastructure",
        "r2inspect.utils",
    )
    _saved_levels = {name: _logging.getLogger(name).level for name in _logger_names}

    try:
        import r2inspect.infrastructure.ssdeep_loader as _ssdeep_loader
    except ImportError:
        _ssdeep_loader = None
    _saved_ssdeep = _ssdeep_loader._ssdeep_module if _ssdeep_loader is not None else None

    import sys as _sys

    _ssdeep_in_modules = "ssdeep" in _sys.modules
    _saved_ssdeep_mod = _sys.modules.get("ssdeep")

    try:
        from r2inspect.schemas.converter_runtime import ResultConverterImpl as _RC
    except ImportError:
        _RC = None
    _saved_schema = dict(_RC._schema_registry) if _RC is not None else None

    try:
        import r2inspect.cli.batch_discovery_runtime as _bdr
    except ImportError:
        _bdr = None
    try:
        import r2inspect.cli.batch_processing as _bp
    except ImportError:
        _bp = None
    _saved_bdr_magic = _bdr.magic if _bdr is not None else None
    _saved_bp_magic = _bp.magic if _bp is not None else None

    try:
        from r2inspect.cli import display as _display
    except ImportError:
        _display = None
    try:
        from r2inspect.cli import display_base as _display_base
    except ImportError:
        _display_base = None
    _saved_display_console = getattr(_display, "console", None)
    _saved_display_base_console = getattr(_display_base, "console", None)

    yield

    if _display is not None and _saved_display_console is not None:
        _display.console = _saved_display_console
    if _display_base is not None and _saved_display_base_console is not None:
        _display_base.console = _saved_display_base_console

    if _saved_cwd is not None:
        try:
            _os.chdir(_saved_cwd)
        except OSError:
            pass
    for _name, _level in _saved_levels.items():
        _logging.getLogger(_name).setLevel(_level)
    if _ssdeep_loader is not None:
        _ssdeep_loader._ssdeep_module = _saved_ssdeep
    if _ssdeep_in_modules:
        _sys.modules["ssdeep"] = _saved_ssdeep_mod
    else:
        _sys.modules.pop("ssdeep", None)
    if _bdr is not None:
        _bdr.magic = _saved_bdr_magic
    if _bp is not None:
        _bp.magic = _saved_bp_magic
    if _RC is not None and _saved_schema is not None:
        _RC._schema_registry.clear()
        _RC._schema_registry.update(_saved_schema)
    try:
        from r2inspect.modules.yara_analyzer import clear_yara_cache

        clear_yara_cache()
    except ImportError:
        pass
    try:
        from r2inspect.error_handling.classifier import reset_global_error_manager

        reset_global_error_manager()
    except ImportError:
        pass
    # The circuit-breaker registry is a process-global dict keyed by func id.
    # Tests that exercise circuit breaking leave entries behind; one with a
    # None policy poisons every later get_circuit_breaker_stats() call. Clear it
    # between tests so the registry never leaks across the suite.
    try:
        from r2inspect.error_handling import unified_handler_circuit_support as _cb

        with _cb._circuit_lock:
            _cb._circuit_breakers.clear()
    except ImportError:
        pass


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Run display_sections tests early to avoid coverage interference."""
    display_items = []
    other_items = []
    for item in items:
        if "display_sections" in item.nodeid:
            display_items.append(item)
        else:
            other_items.append(item)
    items[:] = display_items + other_items
