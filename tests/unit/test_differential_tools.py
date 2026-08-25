from __future__ import annotations

from pathlib import Path

from benchmarks.differential_tools import _tool_findings, compare_report
from benchmarks.run_corpus import _load_manifest
from r2inspect.schemas.report_v1 import FindingV1, ReportV1


def test_specialist_payloads_are_normalized() -> None:
    assert _tool_findings("capa", {"rules": {"rule.one": {}}}) == {"rule.one"}
    assert _tool_findings("floss", {"strings": ["one"], "decoded_strings": ["two"]}) == {
        "one",
        "two",
    }
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


def test_real_manifest_requires_provenance_and_hashes(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        '{"corpus_kind":"real_labeled","provenance":{"source":"x","dataset_version":"1","labeling_method":"review"},"cases":[{"sample":"a","class":"benign","sha256":"'
        + "a" * 64
        + '"}]}',
        encoding="utf-8",
    )
    assert _load_manifest(path)["corpus_kind"] == "real_labeled"
