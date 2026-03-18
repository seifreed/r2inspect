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
def cap_test_resources() -> None:
    """
    Apply aggressive resource caps during tests to avoid overloading the machine.

    r2inspect test mode enables:
      - Single worker/thread execution (no parallel r2 sessions)
      - Lightweight analysis mode (skips heavy aaa analysis)
      - Disabled r2 plugins to reduce overhead
      - Memory and CPU limits to prevent runaway processes

    Caps are configurable via env vars:
      - R2INSPECT_MAX_WORKERS (defaults to 1 in test mode)
      - R2INSPECT_MAX_THREADS (defaults to 1 in test mode)
      - R2INSPECT_DISABLE_PLUGINS (defaults to 1)
      - R2INSPECT_TEST_MODE (defaults to 1, enables lightweight analysis)
      - R2INSPECT_TEST_MAX_CPU_SECONDS (defaults to 300)
      - R2INSPECT_TEST_MAX_AS_MB (defaults to 1024)
      - R2INSPECT_ANALYSIS_DEPTH (defaults to 1 in test mode, use aa not aaa)
    """
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
        try:
            target.symlink_to(source)
        except OSError:
            target.write_bytes(source.read_bytes())
        created_files.append(target)

    yield

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


@pytest.fixture(autouse=True, scope="function")
def cleanup_r2_processes():
    """Cleanup any orphaned radare2 processes after each test."""
    yield
    # radare2 does not run on Windows; skip the expensive process scan there
    if sys.platform == "win32":
        return
    # Post-test cleanup
    try:
        import psutil

        current_pid = os.getpid()
        for proc in psutil.process_iter(["name", "pid"]):
            try:
                name = proc.info.get("name") or ""
                if "radare2" in name.lower() and proc.info.get("pid") != current_pid:
                    proc.terminate()
                    proc.wait(timeout=2)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                pass
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
