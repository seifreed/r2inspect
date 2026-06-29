"""Import-based anti-analysis OR checks must use r2 grep comma syntax.

r2's ~ grep ORs keywords with ',' -- '|' is a shell pipe, so a command like
"ii~Sleep|ii~Delay" only ever matched "Sleep" (the rest piped to the shell).
These tests pin the comma form: detection now fires on a SECOND OR-term,
which the old pipe form could never reach. No mocks, no monkeypatch.
"""

from __future__ import annotations

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.domain.formats.anti_analysis import ENVIRONMENT_CHECK_COMMANDS
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.testing.fake_r2 import FakeR2


def _detector(cmd_map: dict[str, str]) -> AntiAnalysisDetector:
    return AntiAnalysisDetector(R2PipeAdapter(FakeR2(cmd_map=cmd_map)))


def test_sandbox_sleep_delay_detects_via_second_term():
    det = _detector({"ii~Sleep,NtDelayExecution": "0x3000 NtDelayExecution"})
    result = det._detect_anti_sandbox_detailed()
    assert any(e.get("type") == "Sleep/Delay Calls" for e in result["evidence"])


def test_sandbox_delay_load_imports_do_not_false_positive():
    """DLL delay-LOAD runtime imports must not be read as sandbox-evasion sleeps.
    The grep targets Sleep/NtDelayExecution, so a binary that only imports
    ResolveDelayLoadedAPI / DelayLoadFailureHook yields no Sleep/Delay evidence."""
    det = _detector({"ii~Sleep,NtDelayExecution": ""})
    result = det._detect_anti_sandbox_detailed()
    assert not any(e.get("type") == "Sleep/Delay Calls" for e in result["evidence"])


def test_sandbox_enumeration_detects_via_third_term():
    det = _detector({"ii~Process32,Module32": "0x1 Module32"})
    result = det._detect_anti_sandbox_detailed()
    assert any(e.get("type") == "Environment Enumeration" for e in result["evidence"])


def test_environment_info_check_detects_via_second_term():
    det = _detector({"ii~GetSystemInfo,GlobalMemoryStatus": "0x1 GlobalMemoryStatus"})
    checks = det._detect_environment_checks()
    assert any(c.get("type") == "System Info Check" for c in checks)


def test_environment_process_enum_detects_via_second_term():
    det = _detector({"ii~CreateToolhelp32Snapshot,Process32": "0x1 Process32"})
    checks = det._detect_environment_checks()
    assert any(c.get("type") == "Process Enumeration" for c in checks)


def test_import_based_env_commands_use_comma_not_pipe():
    import_cmds = [cmd for cmd, *_ in ENVIRONMENT_CHECK_COMMANDS if cmd.startswith("ii~")]
    assert import_cmds
    for cmd in import_cmds:
        assert "|" not in cmd
        assert "," in cmd


def test_environment_check_commands_drop_loose_iz_terms():
    cmds = [cmd for cmd, *_ in ENVIRONMENT_CHECK_COMMANDS]
    for cmd in cmds:
        assert "|" not in cmd
    assert any(cmd == "iz~GetUserName" for cmd in cmds)
    assert any(cmd == "iz~GetComputerName" for cmd in cmds)
    assert not any("USER" in cmd and cmd != "iz~GetUserName" for cmd in cmds)
