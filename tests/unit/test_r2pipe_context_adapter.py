#!/usr/bin/env python3
"""Tests for r2pipe_context.py -- no mocks, no monkeypatch, no @patch.

Uses FakeR2 + R2PipeAdapter to test actual adapter behavior through
the context-manager helpers in r2pipe_context.
"""

import json
import tempfile
from contextlib import contextmanager
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.adapters.r2pipe_context import _close_r2pipe, open_r2_adapter


# ---------------------------------------------------------------------------
# FakeR2 -- lightweight stand-in for r2pipe instances
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in with cmd/cmdj and cleanup tracking."""

    def __init__(
        self,
        *,
        cmd_map: dict[str, str] | None = None,
        cmdj_map: dict[str, Any] | None = None,
    ) -> None:
        self.cmd_map = cmd_map or {}
        self.cmdj_map = cmdj_map or {}
        self.quit_called = False
        self.process: Any = None  # optionally set by tests

    def cmd(self, command: str) -> str:
        return self.cmd_map.get(command, "")

    def cmdj(self, command: str) -> Any:
        val = self.cmdj_map.get(command)
        if isinstance(val, Exception):
            raise val
        return val

    def quit(self) -> None:
        self.quit_called = True


class FakeProcess:
    """Simulates a subprocess.Popen-like object for _close_r2pipe tests."""

    def __init__(self, *, poll_returns: int | None = 0) -> None:
        self._poll_returns = poll_returns
        self.stdin = FakeStream()
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self) -> int | None:
        return self._poll_returns

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float = 0) -> int:
        self.waited = True
        return 0


class FakeStream:
    """Simulates a closeable stream."""

    def __init__(self, *, raise_on_close: bool = False) -> None:
        self.closed = False
        self._raise = raise_on_close

    def close(self) -> None:
        if self._raise:
            raise OSError("stream close failed")
        self.closed = True


# ---------------------------------------------------------------------------
# Helper -- build an R2PipeAdapter from a FakeR2 directly
# ---------------------------------------------------------------------------


def _make_adapter(**kw: Any) -> tuple[FakeR2, R2PipeAdapter]:
    fake = FakeR2(**kw)
    return fake, R2PipeAdapter(fake)


# ===================================================================
# Tests for R2PipeAdapter constructed with FakeR2
# ===================================================================


class TestR2PipeAdapterWithFakeR2:
    """Verify adapter behaviour driven through a FakeR2 backend."""

    def test_adapter_wraps_fake_r2(self):
        fake, adapter = _make_adapter()
        assert adapter.r2 is fake

    def test_adapter_repr(self):
        _, adapter = _make_adapter()
        assert "R2PipeAdapter" in repr(adapter)

    def test_adapter_str(self):
        _, adapter = _make_adapter()
        assert "radare2" in str(adapter).lower() or "R2PipeAdapter" in str(adapter)

    def test_cmd_returns_string(self):
        _, adapter = _make_adapter(cmd_map={"i": "file info"})
        assert adapter.cmd("i") == "file info"

    def test_cmd_empty_command(self):
        _, adapter = _make_adapter()
        result = adapter.cmd("nonexistent")
        assert isinstance(result, str)

    def test_cmdj_returns_json_data(self):
        data = {"arch": "x86", "bits": 32}
        _, adapter = _make_adapter(cmdj_map={"ij": data})
        result = adapter.cmdj("ij")
        assert result == data

    def test_cmdj_returns_none_on_missing_command(self):
        _, adapter = _make_adapter()
        result = adapter.cmdj("ij")
        assert result is None

    def test_cmdj_suppresses_exception(self):
        """The adapter's cmdj wraps silent_cmdj, which suppresses errors."""
        _, adapter = _make_adapter(cmdj_map={"ij": RuntimeError("boom")})
        result = adapter.cmdj("ij")
        # silent_cmdj catches the RuntimeError and returns the default (None)
        assert result is None

    def test_execute_command_json_dict(self):
        data = {"core": {"file": "test.bin"}}
        _, adapter = _make_adapter(cmdj_map={"ij": data})
        result = adapter.execute_command("ij")
        assert result == data

    def test_execute_command_json_list(self):
        sections = [{"name": ".text", "size": 1024}]
        _, adapter = _make_adapter(cmdj_map={"iSj": sections})
        result = adapter.execute_command("iSj")
        assert result == sections

    def test_execute_command_list_returns_empty_on_missing(self):
        _, adapter = _make_adapter()
        result = adapter.execute_command("iSj")
        assert result == []

    def test_execute_command_text(self):
        _, adapter = _make_adapter(cmd_map={"i": "arch x86"})
        result = adapter.execute_command("i")
        assert result == "arch x86"

    def test_execute_command_empty_string_returns_none(self):
        _, adapter = _make_adapter()
        result = adapter.execute_command("")
        assert result is None

    def test_execute_command_whitespace_returns_none(self):
        _, adapter = _make_adapter()
        result = adapter.execute_command("   ")
        assert result is None

    def test_adapter_rejects_none_instance(self):
        with pytest.raises(ValueError, match="cannot be None"):
            R2PipeAdapter(None)


# ===================================================================
# Tests for _close_r2pipe (direct unit tests, no mocks)
# ===================================================================


class TestCloseR2Pipe:
    """Verify the _close_r2pipe helper handles cleanup correctly."""

    def test_quit_called(self):
        fake = FakeR2()
        _close_r2pipe(fake)
        assert fake.quit_called

    def test_no_process_attribute(self):
        fake = FakeR2()
        assert fake.process is None
        # Should not raise even without a process
        _close_r2pipe(fake)
        assert fake.quit_called

    def test_process_streams_closed(self):
        fake = FakeR2()
        proc = FakeProcess()
        fake.process = proc
        _close_r2pipe(fake)
        assert proc.stdin.closed
        assert proc.stdout.closed
        assert proc.stderr.closed

    def test_process_already_finished(self):
        fake = FakeR2()
        proc = FakeProcess(poll_returns=0)  # already exited
        fake.process = proc
        _close_r2pipe(fake)
        # Should not attempt terminate since poll() != None
        assert not proc.terminated

    def test_process_still_running_gets_terminated(self):
        fake = FakeR2()
        proc = FakeProcess(poll_returns=None)  # still running
        fake.process = proc
        _close_r2pipe(fake)
        assert proc.terminated
        assert proc.waited

    def test_stream_close_failure_is_swallowed(self):
        fake = FakeR2()
        proc = FakeProcess()
        proc.stdin = FakeStream(raise_on_close=True)
        proc.stdout = FakeStream(raise_on_close=True)
        proc.stderr = FakeStream(raise_on_close=True)
        fake.process = proc
        # Should not raise despite all streams failing to close
        _close_r2pipe(fake)
        assert fake.quit_called

    def test_quit_failure_is_swallowed(self):
        class FailQuitR2(FakeR2):
            def quit(self) -> None:
                raise OSError("quit failed")

        fake = FailQuitR2()
        # Should not raise
        _close_r2pipe(fake)

    def test_terminate_failure_triggers_kill(self):
        """When terminate raises, _close_r2pipe falls back to kill."""

        class FailTermProc(FakeProcess):
            def terminate(self) -> None:
                raise OSError("terminate failed")

        fake = FakeR2()
        proc = FailTermProc(poll_returns=None)
        fake.process = proc
        _close_r2pipe(fake)
        assert proc.killed

    def test_process_with_no_streams(self):
        """Process exists but stdin/stdout/stderr are None."""
        fake = FakeR2()
        proc = FakeProcess()
        proc.stdin = None
        proc.stdout = None
        proc.stderr = None
        fake.process = proc
        # Should not raise
        _close_r2pipe(fake)


# ===================================================================
# Tests for cached_query via FakeR2 + R2PipeAdapter
# ===================================================================


class TestCachedQuery:
    """Verify _cached_query caching and validation through the real adapter."""

    def test_cached_query_list(self):
        sections = [{"name": ".text", "size": 4096}]
        _, adapter = _make_adapter(cmdj_map={"iSj": sections})
        result = adapter._cached_query("iSj", "list")
        assert result == sections

    def test_cached_query_dict(self):
        info = {"arch": "x86", "bits": 64}
        _, adapter = _make_adapter(cmdj_map={"ij": info})
        result = adapter._cached_query("ij", "dict")
        assert result == info

    def test_cached_query_returns_cached_on_second_call(self):
        sections = [{"name": ".data", "size": 512}]
        fake, adapter = _make_adapter(cmdj_map={"iSj": sections})
        first = adapter._cached_query("iSj", "list")
        # Modify the fake to return something different
        fake.cmdj_map["iSj"] = [{"name": ".bss"}]
        second = adapter._cached_query("iSj", "list")
        # Should still get cached result
        assert first == second == sections

    def test_cached_query_no_cache_mode(self):
        sections = [{"name": ".text", "size": 100}]
        fake, adapter = _make_adapter(cmdj_map={"iSj": sections})
        first = adapter._cached_query("iSj", "list", cache=False)
        assert first == sections
        # Change response -- without cache it should pick up new value
        new_sections = [{"name": ".data", "size": 200}]
        fake.cmdj_map["iSj"] = new_sections
        second = adapter._cached_query("iSj", "list", cache=False)
        assert second == new_sections

    def test_cached_query_empty_returns_default_list(self):
        _, adapter = _make_adapter()
        result = adapter._cached_query("iSj", "list")
        assert result == []

    def test_cached_query_empty_returns_default_dict(self):
        _, adapter = _make_adapter()
        result = adapter._cached_query("ij", "dict")
        assert result == {}

    def test_cached_query_custom_default(self):
        _, adapter = _make_adapter()
        default = [{"fallback": True}]
        result = adapter._cached_query("iSj", "list", default=default)
        assert result == default

    def test_cached_query_error_msg_logged(self):
        """Exercises the error_msg path without crashing."""
        _, adapter = _make_adapter()
        result = adapter._cached_query("iSj", "list", error_msg="No sections found")
        assert result == []


# ===================================================================
# Tests for open_r2_adapter used with FakeR2 (adapter-wrapping path)
# ===================================================================


class TestOpenR2AdapterBehavior:
    """Test the adapter wrapper's interface through real objects.

    Note: open_r2_adapter itself calls r2pipe.open which requires
    a real binary. We test the *adapter behavior* instead, which is
    the actual value being tested.
    """

    def test_adapter_is_context_aware(self):
        """Adapter can be used outside a context manager too."""
        fake, adapter = _make_adapter(cmdj_map={"ij": {"arch": "arm"}})
        assert adapter.cmdj("ij") == {"arch": "arm"}

    def test_adapter_operations_with_sections(self):
        sections = [
            {"name": ".text", "size": 4096, "paddr": 0x1000},
            {"name": ".data", "size": 2048, "paddr": 0x2000},
        ]
        _, adapter = _make_adapter(cmdj_map={"iSj": sections})
        result = adapter.execute_command("iSj")
        assert len(result) == 2
        assert result[0]["name"] == ".text"

    def test_adapter_operations_with_imports(self):
        imports = [
            {"name": "printf", "type": "FUNC"},
            {"name": "malloc", "type": "FUNC"},
        ]
        _, adapter = _make_adapter(cmdj_map={"iij": imports})
        result = adapter.execute_command("iij")
        assert len(result) == 2

    def test_adapter_operations_with_exports(self):
        exports = [{"name": "main", "type": "FUNC", "vaddr": 0x401000}]
        _, adapter = _make_adapter(cmdj_map={"iEj": exports})
        result = adapter.execute_command("iEj")
        assert isinstance(result, list)
        assert result[0]["name"] == "main"

    def test_adapter_cmd_text_output(self):
        _, adapter = _make_adapter(cmd_map={"pd 10": "0x00401000 push ebp"})
        result = adapter.cmd("pd 10")
        assert "push ebp" in result

    def test_multiple_commands_sequentially(self):
        fake, adapter = _make_adapter(
            cmdj_map={
                "ij": {"arch": "x86", "bits": 64},
                "iSj": [{"name": ".text"}],
            },
            cmd_map={"i": "file /bin/ls"},
        )
        info = adapter.cmdj("ij")
        sections = adapter.execute_command("iSj")
        text = adapter.cmd("i")
        assert info["arch"] == "x86"
        assert len(sections) == 1
        assert "file" in text

    def test_adapter_thread_safe_flag(self):
        _, adapter = _make_adapter()
        assert adapter.thread_safe is False


# ===================================================================
# Tests for _close_r2pipe edge-case resilience
# ===================================================================


class TestCloseR2PipeEdgeCases:
    """Additional edge cases for the cleanup path."""

    def test_kill_also_fails_silently(self):
        """When both terminate and kill fail, no exception leaks."""

        class FailAllProc(FakeProcess):
            def terminate(self) -> None:
                raise OSError("terminate failed")

            def kill(self) -> None:
                raise OSError("kill failed")

        fake = FakeR2()
        proc = FailAllProc(poll_returns=None)
        fake.process = proc
        # Must not raise
        _close_r2pipe(fake)

    def test_wait_timeout_triggers_kill(self):
        """When wait() raises TimeoutExpired-like, should try kill."""

        class SlowProc(FakeProcess):
            def wait(self, timeout: float = 0) -> int:
                raise TimeoutError("wait timed out")

        fake = FakeR2()
        proc = SlowProc(poll_returns=None)
        fake.process = proc
        _close_r2pipe(fake)
        assert proc.terminated
        # After wait fails, kill should be attempted because poll_returns=None
        # on subsequent poll check
        assert proc.killed

    def test_partial_streams(self):
        """Only some streams exist on the process."""
        fake = FakeR2()
        proc = FakeProcess()
        proc.stdin = FakeStream()
        proc.stdout = None
        proc.stderr = FakeStream()
        fake.process = proc
        _close_r2pipe(fake)
        assert proc.stdin.closed
        assert proc.stderr.closed


# ===================================================================
# Tests for forced adapter error via environment variable
# ===================================================================


def _always_raise_injector(method: str) -> None:
    raise RuntimeError("Forced adapter error")


def _selective_raise_injector(*methods: str):
    def _injector(method: str) -> None:
        if method in methods:
            raise RuntimeError("Forced adapter error")

    return _injector


class TestForcedAdapterError:
    """Verify _maybe_force_error through the fault_injector mechanism."""

    def test_no_injector_no_error(self):
        _, adapter = _make_adapter()
        # With no fault_injector set, should work fine
        result = adapter._cached_query("iSj", "list")
        assert result == []

    def test_forced_error_all(self):
        fake = FakeR2()
        adapter = R2PipeAdapter(fake, fault_injector=_always_raise_injector)
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._cached_query("iSj", "list")

    def test_forced_error_specific_method(self):
        fake = FakeR2()
        adapter = R2PipeAdapter(fake, fault_injector=_selective_raise_injector("_cached_query"))
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._cached_query("iSj", "list")

    def test_forced_error_unrelated_method(self):
        fake = FakeR2()
        adapter = R2PipeAdapter(fake, fault_injector=_selective_raise_injector("some_other_method"))
        # Should NOT raise because method name doesn't match
        result = adapter._cached_query("iSj", "list")
        assert result == []

    def test_forced_error_always(self):
        fake = FakeR2()
        adapter = R2PipeAdapter(fake, fault_injector=_always_raise_injector)
        with pytest.raises(RuntimeError):
            adapter._cached_query("ij", "dict")
