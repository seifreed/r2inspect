"""Pytest configuration for shared fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

try:
    import resource as _resource
except ImportError:
    _resource = None  # type: ignore[assignment]

import pytest

# =============================================================================
# Test Resource Limits Configuration
# =============================================================================
# These defaults are aggressive to prevent tests from overwhelming the machine.
# Override via environment variables if needed.

DEFAULT_TEST_MAX_WORKERS = "1"  # Single worker to reduce r2 process spawning
DEFAULT_TEST_MAX_THREADS = "1"  # Single thread for r2 operations
DEFAULT_TEST_MEMORY_LIMIT_MB = 1024  # 1GB memory limit per test process
DEFAULT_TEST_CPU_LIMIT_SECONDS = 300  # 5 minute CPU time limit per test session


def _infer_file_format(path: Path) -> str:
    data = path.read_bytes()[:4]
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return "MACHO"
    return "Unknown"


def _build_expected_payload(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    file_format = _infer_file_format(path)
    return {
        "file_format": file_format,
        "name": path.name,
        "size": path.stat().st_size,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "file_info": {
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "file_type": file_format,
        },
        "hashing": {},
        "security": {},
    }


def _ensure_expected_snapshots(fixtures_dir: Path) -> None:
    expected_dir = fixtures_dir / "expected"
    expected_dir.mkdir(parents=True, exist_ok=True)
    snapshot_names = (
        "hello_pe.exe",
        "hello_elf",
        "hello_macho",
        "edge_packed.bin",
        "edge_tiny.bin",
        "edge_bad_pe.bin",
        "edge_high_entropy.bin",
    )
    for file_name in snapshot_names:
        fixture_path = fixtures_dir / file_name
        if not fixture_path.exists():
            continue
        payload = _build_expected_payload(fixture_path)
        out_name = file_name.replace(".exe", "").replace(".bin", "") + ".json"
        (expected_dir / out_name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


@pytest.fixture(scope="session")
def samples_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return a legacy-compatible fixtures directory backed by test binaries repo."""
    repo_root = Path(__file__).resolve().parent.parent
    configured = os.getenv("R2INSPECT_TEST_BINARIES_DIR", "").strip()
    candidate_roots = []
    if configured:
        candidate_roots.append(Path(configured))
    candidate_roots.append(repo_root.parent / "r2inspect-test-binaries")
    candidate_roots.append(repo_root / "samples" / "fixtures")

    source_root = next((path for path in candidate_roots if path.exists()), None)
    if source_root is None:
        pytest.skip(
            "No fixture binaries found. Set R2INSPECT_TEST_BINARIES_DIR or clone "
            "../r2inspect-test-binaries."
        )

    if (source_root / "hello_pe.exe").exists():
        # Legacy in-repo layout already available.
        return source_root

    # Build a legacy fixtures layout expected by existing tests.
    legacy_dir = tmp_path_factory.mktemp("legacy_fixtures")
    mapping = {
        "hello_pe.exe": source_root / "pe" / "hello_pe.exe",
        "hello_elf": source_root / "elf" / "hello_elf",
        "hello_macho": source_root / "mach0" / "hello_macho",
        "hello_macho_stripped": source_root / "mach0" / "hello_macho_stripped",
        "edge_tiny.bin": source_root / "edge" / "edge_tiny.bin",
        "edge_packed.bin": source_root / "edge" / "edge_packed.bin",
        "edge_bad_pe.bin": source_root / "edge" / "edge_bad_pe.bin",
        "edge_high_entropy.bin": source_root / "edge" / "edge_high_entropy.bin",
    }

    for target_name, source_path in mapping.items():
        if not source_path.exists():
            continue
        target_path = legacy_dir / target_name
        try:
            target_path.symlink_to(source_path)
        except OSError:
            target_path.write_bytes(source_path.read_bytes())

    _ensure_expected_snapshots(legacy_dir)
    return legacy_dir


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
def ensure_legacy_samples_tree(samples_dir: Path) -> None:
    """
    Ensure legacy samples/fixtures paths exist for tests with hardcoded paths.

    The project migrated binaries out of this repo; this recreates the legacy
    tree as symlinks (or copies) during test execution only.
    """
    repo_root = Path(__file__).resolve().parent.parent
    legacy_fixtures = repo_root / "samples" / "fixtures"
    created = False
    created_files: list[Path] = []

    if not legacy_fixtures.exists():
        legacy_fixtures.mkdir(parents=True, exist_ok=True)
        created = True

    for source in samples_dir.iterdir():
        target = legacy_fixtures / source.name
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
            legacy_fixtures.rmdir()
            (legacy_fixtures.parent).rmdir()
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
