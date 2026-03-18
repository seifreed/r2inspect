#!/usr/bin/env python3
"""Tests for r2pipe_context.py -- zero mocks, zero monkeypatch, zero @patch.

Uses the FakeR2 pattern: a plain object with cmdj_map / cmd_map dicts
that is fed into R2PipeAdapter.  For the context-manager helpers we test
_close_r2pipe directly with purpose-built fake process objects.
"""

import types

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.adapters.r2pipe_context import _close_r2pipe


# ── FakeR2 ──────────────────────────────────────────────────────────


class FakeR2:
    """Minimal r2pipe stand-in that routes cmdj/cmd via lookup maps."""

    def __init__(self, cmdj_map=None, cmd_map=None, *, quit_raises=False):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}
        self.quit_called = False
        self._quit_raises = quit_raises
        self.process = None  # may be overridden in tests

    def cmdj(self, command):
        return self.cmdj_map.get(command, {})

    def cmd(self, command):
        return self.cmd_map.get(command, "")

    def quit(self):
        if self._quit_raises:
            raise OSError("quit failed")
        self.quit_called = True


class FakeStream:
    """A closeable stream stand-in."""

    def __init__(self, *, close_raises=False):
        self.closed = False
        self._close_raises = close_raises

    def close(self):
        if self._close_raises:
            raise OSError("stream close failed")
        self.closed = True


class FakeProcess:
    """A minimal subprocess.Popen stand-in."""

    def __init__(self, *, poll_value=None, terminate_raises=False, kill_raises=False):
        self.stdin = FakeStream()
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self._poll_value = poll_value
        self._terminate_raises = terminate_raises
        self._kill_raises = kill_raises
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self):
        return self._poll_value

    def terminate(self):
        if self._terminate_raises:
            raise OSError("terminate failed")
        self.terminated = True
        self._poll_value = 0  # after terminate, poll returns exit code

    def wait(self, timeout=None):
        self.waited = True

    def kill(self):
        if self._kill_raises:
            raise OSError("kill failed")
        self.killed = True


# ── R2PipeAdapter with FakeR2 ───────────────────────────────────────


class TestR2PipeAdapterWithFakeR2:
    """Verify R2PipeAdapter wraps FakeR2 correctly."""

    def test_adapter_construction(self):
        r2 = FakeR2()
        adapter = R2PipeAdapter(r2)
        assert adapter.r2 is r2

    def test_adapter_cmd_delegates(self):
        r2 = FakeR2(cmd_map={"i": "file info here"})
        adapter = R2PipeAdapter(r2)
        assert adapter.cmd("i") == "file info here"

    def test_adapter_cmd_default_empty(self):
        r2 = FakeR2()
        adapter = R2PipeAdapter(r2)
        assert adapter.cmd("nonexistent") == ""

    def test_adapter_cmdj_delegates(self):
        info = {"arch": "x86", "bits": 64}
        r2 = FakeR2(cmdj_map={"ij": info})
        adapter = R2PipeAdapter(r2)
        # cmdj goes through silent_cmdj; the raw object is returned
        result = adapter.cmdj("ij")
        assert result == info

    def test_adapter_repr(self):
        r2 = FakeR2()
        adapter = R2PipeAdapter(r2)
        assert "R2PipeAdapter" in repr(adapter)

    def test_adapter_str(self):
        r2 = FakeR2()
        adapter = R2PipeAdapter(r2)
        assert "R2PipeAdapter" in str(adapter)

    def test_adapter_rejects_none(self):
        with pytest.raises(ValueError, match="cannot be None"):
            R2PipeAdapter(None)


# ── _close_r2pipe cleanup logic ─────────────────────────────────────


class TestCloseR2Pipe:
    """Test _close_r2pipe with real fake objects -- no mocks."""

    def test_quit_is_called(self):
        r2 = FakeR2()
        _close_r2pipe(r2)
        assert r2.quit_called

    def test_quit_exception_is_swallowed(self):
        r2 = FakeR2(quit_raises=True)
        _close_r2pipe(r2)  # should not raise
        assert not r2.quit_called  # quit raised before flag was set

    def test_no_process_attribute_returns_early(self):
        r2 = FakeR2()
        r2.process = None
        _close_r2pipe(r2)
        assert r2.quit_called

    def test_streams_are_closed(self):
        r2 = FakeR2()
        proc = FakeProcess(poll_value=0)
        r2.process = proc
        _close_r2pipe(r2)
        assert proc.stdin.closed
        assert proc.stdout.closed
        assert proc.stderr.closed

    def test_stream_close_error_is_swallowed(self):
        r2 = FakeR2()
        proc = FakeProcess(poll_value=0)
        proc.stdin = FakeStream(close_raises=True)
        proc.stdout = FakeStream(close_raises=True)
        proc.stderr = FakeStream(close_raises=True)
        r2.process = proc
        _close_r2pipe(r2)  # should not raise

    def test_process_already_exited_no_terminate(self):
        r2 = FakeR2()
        proc = FakeProcess(poll_value=0)  # poll != None => already exited
        r2.process = proc
        _close_r2pipe(r2)
        assert not proc.terminated

    def test_running_process_is_terminated(self):
        r2 = FakeR2()
        proc = FakeProcess(poll_value=None)  # poll == None => still running
        r2.process = proc
        _close_r2pipe(r2)
        assert proc.terminated
        assert proc.waited

    def test_terminate_failure_falls_back_to_kill(self):
        r2 = FakeR2()
        proc = FakeProcess(poll_value=None, terminate_raises=True)
        r2.process = proc
        _close_r2pipe(r2)
        assert proc.killed

    def test_kill_failure_is_swallowed(self):
        r2 = FakeR2()
        proc = FakeProcess(poll_value=None, terminate_raises=True, kill_raises=True)
        r2.process = proc
        _close_r2pipe(r2)  # should not raise

    def test_partial_streams_none(self):
        """Some streams may be None (e.g., if not piped)."""
        r2 = FakeR2()
        proc = FakeProcess(poll_value=0)
        proc.stdin = None
        proc.stderr = None
        r2.process = proc
        _close_r2pipe(r2)
        assert proc.stdout.closed

    def test_missing_process_attribute(self):
        """r2 instance without a process attribute at all."""
        r2 = FakeR2()
        delattr(r2, "process")  # remove it entirely
        _close_r2pipe(r2)
        assert r2.quit_called


# ── Adapter as context-manager substitute ───────────────────────────


class TestAdapterContextUsage:
    """
    Test the pattern that open_r2_adapter provides:
    yield R2PipeAdapter(r2) -- verified without r2pipe.open.
    """

    def test_adapter_wraps_fake_r2_for_cmd(self):
        r2 = FakeR2(cmd_map={"aaa": "analysis done", "iI": "info output"})
        adapter = R2PipeAdapter(r2)
        assert adapter.cmd("aaa") == "analysis done"
        assert adapter.cmd("iI") == "info output"

    def test_adapter_wraps_fake_r2_for_execute_command(self):
        sections = [{"name": ".text", "size": 4096}]
        r2 = FakeR2(cmdj_map={"iSj": sections})
        adapter = R2PipeAdapter(r2)
        result = adapter.execute_command("iSj")
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == ".text"

    def test_execute_command_non_json(self):
        r2 = FakeR2(cmd_map={"pdf": "disassembly output"})
        adapter = R2PipeAdapter(r2)
        result = adapter.execute_command("pdf")
        assert result == "disassembly output"

    def test_execute_command_empty_string(self):
        r2 = FakeR2()
        adapter = R2PipeAdapter(r2)
        assert adapter.execute_command("") is None
        assert adapter.execute_command("   ") is None

    def test_cleanup_via_close_r2pipe(self):
        """Simulate the full open-use-close lifecycle."""
        r2 = FakeR2(cmd_map={"i": "binary info"})
        proc = FakeProcess(poll_value=None)
        r2.process = proc
        adapter = R2PipeAdapter(r2)
        # Use the adapter
        assert adapter.cmd("i") == "binary info"
        # Cleanup (same as what open_r2pipe's finally block does)
        _close_r2pipe(r2)
        assert r2.quit_called
        assert proc.terminated

    def test_cleanup_after_exception(self):
        """Cleanup still works after user code raises."""
        r2 = FakeR2(cmd_map={"px 16": "hex dump"})
        proc = FakeProcess(poll_value=None)
        r2.process = proc
        adapter = R2PipeAdapter(r2)
        try:
            _ = adapter.cmd("px 16")
            raise RuntimeError("simulated error")
        except RuntimeError:
            pass
        _close_r2pipe(r2)
        assert r2.quit_called
        assert proc.terminated


# ── Nested adapter usage ────────────────────────────────────────────


class TestNestedAdapters:
    """Verify multiple independent adapters do not interfere."""

    def test_two_adapters_independent(self):
        r2_a = FakeR2(cmd_map={"i": "binary_a"})
        r2_b = FakeR2(cmd_map={"i": "binary_b"})
        adapter_a = R2PipeAdapter(r2_a)
        adapter_b = R2PipeAdapter(r2_b)
        assert adapter_a.cmd("i") == "binary_a"
        assert adapter_b.cmd("i") == "binary_b"

    def test_nested_cleanup(self):
        r2_a = FakeR2()
        r2_b = FakeR2()
        r2_a.process = FakeProcess(poll_value=0)
        r2_b.process = FakeProcess(poll_value=0)
        R2PipeAdapter(r2_a)
        R2PipeAdapter(r2_b)
        _close_r2pipe(r2_b)
        _close_r2pipe(r2_a)
        assert r2_a.quit_called
        assert r2_b.quit_called


# ── execute_command JSON routing ────────────────────────────────────


class TestExecuteCommandRouting:
    """Verify execute_command picks the right path for j-suffix commands."""

    @pytest.mark.parametrize(
        "cmd", ["iSj", "iij", "iEj", "isj", "aflj", "izj", "izzj", "iDj", "agj"]
    )
    def test_list_commands_return_list(self, cmd):
        data = [{"name": "item1"}]
        r2 = FakeR2(cmdj_map={cmd: data})
        adapter = R2PipeAdapter(r2)
        result = adapter.execute_command(cmd)
        assert isinstance(result, list)

    @pytest.mark.parametrize(
        "cmd", ["iSj", "iij", "iEj", "isj", "aflj", "izj", "izzj", "iDj", "agj"]
    )
    def test_list_commands_return_empty_on_none(self, cmd):
        r2 = FakeR2(cmdj_map={cmd: None})
        adapter = R2PipeAdapter(r2)
        result = adapter.execute_command(cmd)
        assert result == []

    def test_dict_json_command(self):
        r2 = FakeR2(cmdj_map={"ij": {"core": {"file": "test.exe"}}})
        adapter = R2PipeAdapter(r2)
        result = adapter.execute_command("ij")
        assert isinstance(result, dict)
        assert result["core"]["file"] == "test.exe"

    def test_dict_json_command_returns_empty_on_none(self):
        r2 = FakeR2(cmdj_map={"ij": None})
        adapter = R2PipeAdapter(r2)
        result = adapter.execute_command("ij")
        assert result == {}
