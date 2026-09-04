import os
import subprocess
import time
import hashlib

from r2inspect.application.report_builder import build_report_v1
from r2inspect.application.result_mapper import build_analysis_result
from r2inspect.modules.external_tool_analyzers import CapaAnalyzer, FlossAnalyzer


def test_external_tools_report_missing_dependencies_explicitly() -> None:
    def missing(_name: str) -> None:
        return None

    assert (
        CapaAnalyzer(filename="sample.exe", executable_lookup=missing).analyze()[
            "library_available"
        ]
        is False
    )
    assert (
        FlossAnalyzer(filename="sample.exe", executable_lookup=missing).analyze()[
            "library_available"
        ]
        is False
    )


def test_external_tools_use_short_timeout_in_test_mode(tmp_path) -> None:
    executable = tmp_path / "slow-tool"
    executable.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(1)\n")
    executable.chmod(os.stat(executable).st_mode | 0o111)
    original_mode = os.environ.get("R2INSPECT_TEST_MODE")
    original_timeout = os.environ.pop("R2INSPECT_CMD_TIMEOUT_SECONDS", None)
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    try:
        started = time.monotonic()
        result = CapaAnalyzer(
            filename="sample.exe", executable_lookup=lambda _name: str(executable)
        ).analyze()
    finally:
        if original_mode is None:
            os.environ.pop("R2INSPECT_TEST_MODE", None)
        else:
            os.environ["R2INSPECT_TEST_MODE"] = original_mode
        if original_timeout is not None:
            os.environ["R2INSPECT_CMD_TIMEOUT_SECONDS"] = original_timeout

    assert result["error"] == "command timed out after 0.2 seconds"
    assert time.monotonic() - started < 1


def test_report_normalizes_capa_and_floss_results() -> None:
    result = build_analysis_result(
        {
            "file_info": {"file_type": "PE"},
            "capa": {"available": True, "result": {"rules": {"send HTTP request": {}}}},
            "floss": {
                "available": True,
                "result": {
                    "strings": {
                        "decoded_strings": ["secret.example"],
                        "static_strings": [{"string": "CreateProcessA", "offset": 42}],
                    }
                },
            },
        }
    )

    report = build_report_v1(result, analysis_id="external", commit="abc", radare2_version="6.1.8")

    assert report.capabilities[0]["name"] == "send HTTP request"
    assert {artifact["value"] for artifact in report.artifacts} == {
        "secret.example",
        "CreateProcessA",
    }


def test_floss_uses_static_string_mode_for_bounded_comparison() -> None:
    assert FlossAnalyzer.command_args == ("--only", "static", "-j")


def test_forensic_floss_uses_full_mode_and_preserves_native_output(tmp_path, monkeypatch) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    commands = []

    def run(command, *, timeout):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"strings": {}}\n', "")

    monkeypatch.setattr("r2inspect.modules.external_tool_analyzers.run_command", run)

    result = FlossAnalyzer(
        filename=str(sample), executable_lookup=lambda _name: "/usr/bin/floss"
    ).analyze(forensic=True)

    assert commands == [["/usr/bin/floss", "-j", str(sample)]]
    assert result["result"] == {"strings": {}}
    assert result["native_output"]["stdout"] == '{"strings": {}}\n'


def test_forensic_external_failure_preserves_native_output(monkeypatch) -> None:
    def run(command, *, timeout):
        return subprocess.CompletedProcess(command, 2, "partial", "failed")

    monkeypatch.setattr("r2inspect.modules.external_tool_analyzers.run_command", run)

    result = CapaAnalyzer(
        filename="sample.exe", executable_lookup=lambda _name: "/usr/bin/capa"
    ).analyze(forensic=True)

    assert result["error"] == "failed"
    assert result["native_output"]["stdout"] == "partial"
    assert result["native_output"]["stderr"] == "failed"


def test_external_tool_reports_binary_version_hash_and_rules(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "capa"
    executable.write_bytes(b"capa-binary")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text("rule")
    monkeypatch.setenv("R2INSPECT_CAPA_RULES", str(rules))
    monkeypatch.setattr(
        "r2inspect.modules.external_tool_support.run_command",
        lambda command, *, timeout: subprocess.CompletedProcess(command, 0, "capa 9.0", ""),
    )
    monkeypatch.setattr(
        "r2inspect.modules.external_tool_analyzers.run_command",
        lambda command, *, timeout: subprocess.CompletedProcess(command, 0, "{}", ""),
    )

    result = CapaAnalyzer(
        filename="sample.exe", executable_lookup=lambda _name: str(executable)
    ).analyze()

    assert result["tool"]["version"] == "capa 9.0"
    assert result["tool"]["sha256"] == hashlib.sha256(b"capa-binary").hexdigest()
    assert result["tool"]["rules"]["source"] == str(rules)
    assert result["tool"]["rules"]["digest"]
