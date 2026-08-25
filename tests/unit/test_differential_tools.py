from __future__ import annotations

import os
from pathlib import Path
import json

import benchmarks.differential_tools as differential_tools
from benchmarks.differential_tools import _tool_findings, compare_report, run_specialist_safe
import benchmarks.run_corpus as corpus_runner
from benchmarks.run_corpus import _load_manifest, run_corpus
from r2inspect.schemas.report_v1 import FindingV1, ReportV1


def test_specialist_payloads_are_normalized() -> None:
    assert _tool_findings("capa", {"rules": {"rule.one": {}}}) == {"rule.one"}
    assert _tool_findings("floss", {"strings": ["one"], "decoded_strings": ["two"]}) == {
        "one",
        "two",
    }
    assert _tool_findings(
        "floss",
        {"strings": {"static_strings": [{"string": "three", "offset": 1}]}},
    ) == {"three"}
    assert _tool_findings("yara", "rule.one sample\n") == {"rule.one"}


def test_compare_report_exposes_disagreement() -> None:
    report = ReportV1(
        tool={"version": "test"},
        analysis={"id": "id", "started_at": "2026-01-01T00:00:00Z", "duration": 0},
        sample={"size": 1},
        findings=[
            FindingV1(
                finding_id="f",
                rule_id="rule.one",
                title="one",
                category="test",
                severity="low",
                confidence=1,
                source_analyzer="test",
                method="test",
            )
        ],
    )
    result = compare_report(report, {"rule.two"})
    assert result["agreement"] == []
    assert result["r2inspect_only"] == ["rule.one"]
    assert result["specialist_only"] == ["rule.two"]


def test_compare_report_uses_tool_specific_domains() -> None:
    report = ReportV1(
        tool={"version": "test"},
        analysis={"id": "id", "started_at": "2026-01-01T00:00:00Z", "duration": 0},
        sample={"size": 1},
        capabilities=[{"source": "capa", "name": "Create Process"}],
        artifacts=[{"source": "floss", "type": "static", "value": "Secret Value"}],
    )
    assert compare_report(report, {"create_process"}, tool="capa")["agreement"] == [
        "Create Process"
    ]
    assert compare_report(report, {"secret-value"}, tool="floss")["agreement"] == ["Secret Value"]


def test_specialist_timeout_is_explicit(tmp_path: Path) -> None:
    def fail(*_args, **_kwargs):
        raise __import__("subprocess").TimeoutExpired("capa", 120)

    original_runner = differential_tools.run_specialist
    differential_tools.run_specialist = fail
    try:
        result = run_specialist_safe("capa", tmp_path / "sample.bin")
    finally:
        differential_tools.run_specialist = original_runner

    assert result["status"] == "timed_out"
    assert result["findings"] == []


def test_specialist_runner_parses_json_command(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    if os.name == "nt":
        tool = tmp_path / "capa.cmd"
        tool.write_text(
            '@echo {"rules": {"rule.one": {}}}\r\n',
            encoding="utf-8",
        )
    else:
        tool = tmp_path / "capa"
        tool.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' '{\"rules\": {\"rule.one\": {}}}'\n",
            encoding="utf-8",
        )
    tool.chmod(0o755)
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{tmp_path}{os.pathsep}{original_path}"
    try:
        assert differential_tools.run_specialist("capa", sample, timeout=2) == {"rule.one"}
    finally:
        os.environ["PATH"] = original_path


def test_real_manifest_requires_provenance_and_hashes(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        '{"corpus_kind":"real_labeled","provenance":{"source":"x","dataset_version":"1","labeling_method":"review"},"cases":[{"sample":"a","class":"benign","sha256":"'
        + "a" * 64
        + '"}]}',
        encoding="utf-8",
    )
    assert _load_manifest(path)["corpus_kind"] == "real_labeled"


def test_real_manifest_metadata_is_preserved_in_evaluation(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"real-labeled-sample")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "r2inspect.benchmark/v1",
                "corpus_kind": "real_labeled",
                "corpus_id": "dataset-v1",
                "provenance": {
                    "source": "licensed-source",
                    "dataset_version": "v1",
                    "labeling_method": "independent-review",
                },
                "classification": {"strategy": "any_finding"},
                "cases": [
                    {
                        "id": "sample-1",
                        "sample": sample.name,
                        "class": "benign",
                        "sha256": "".join([]),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    import hashlib

    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["cases"][0]["sha256"] = hashlib.sha256(sample.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(data), encoding="utf-8")

    def fake_run_case(case, _corpus_dir, reports_dir, _profile, _project_root):
        report = ReportV1(
            tool={"version": "test"},
            analysis={"id": "id", "started_at": "2026-01-01T00:00:00Z", "duration": 0},
            sample={"size": 1},
        )
        path = reports_dir / f"{case['id']}.json"
        path.write_text(report.model_dump_json(), encoding="utf-8")
        return f"reports/{path.name}"

    original_runner = corpus_runner._run_case
    corpus_runner._run_case = fake_run_case
    try:
        result = run_corpus(manifest, tmp_path, tmp_path / "out", project_root=tmp_path)
    finally:
        corpus_runner._run_case = original_runner
    evaluation = json.loads(result.read_text(encoding="utf-8"))
    assert evaluation["corpus_kind"] == "real_labeled"
    assert evaluation["provenance"]["dataset_version"] == "v1"
    assert evaluation["classification"] == {"strategy": "any_finding"}
