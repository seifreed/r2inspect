"""Shared helpers for tests."""

from .batch_fakes import DummyRateLimiter, write_minimal_pe_file
from .cli_runner import run_cli
from .console_fakes import CaptureConsole
from .module_loading import blocked_import, import_fresh
from .pipeline_builders import StaticResultStage, make_stage_context
from .pipeline_fakes import FakeAdapter, FakeConfig
from .r2_fakes import FakeR2Adapter
from .registry_fakes import make_registry
from .session_fakes import FakeSession

__all__ = [
    "CaptureConsole",
    "DummyRateLimiter",
    "FakeAdapter",
    "FakeConfig",
    "FakeR2Adapter",
    "FakeSession",
    "StaticResultStage",
    "blocked_import",
    "import_fresh",
    "make_stage_context",
    "make_registry",
    "run_cli",
    "write_minimal_pe_file",
]
