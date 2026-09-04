from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.calibrate_clustering import calibrate
from r2inspect.application import clustering, report_similarity
from r2inspect.application.clustering import cluster_reports, index_reports, query_index
from r2inspect.application.explain import explain, radare2_commands
from r2inspect.application.report_similarity import feature_similarity, similarity_hashes
from r2inspect.application.rule_packs import RulePackManifest, verify_rule_pack
from r2inspect.schemas.report_v1 import (
    EvidenceV1,
    FindingV1,
    LocationV1,
    ReportV1,
    SampleInfoV1,
)


def _report(rule_ids: list[str]) -> ReportV1:
    return ReportV1(
        tool={"version": "test"},
        analysis={"id": "sample", "started_at": "2026-01-01T00:00:00Z", "duration": 0},
        sample={"size": 1},
        findings=[
            FindingV1(
                finding_id=f"id-{rule_id}",
                rule_id=rule_id,
                title=rule_id,
                category="test",
                severity="low",
                confidence=1,
                source_analyzer="test",
                method="test",
                locations=[LocationV1(virtual_address=0x401000)],
            )
            for rule_id in rule_ids
        ],
    )


def test_explain_includes_radare2_commands() -> None:
    finding = _report(["rule.one"]).findings[0]
    result = explain(_report(["rule.one"]), finding.finding_id)
    assert radare2_commands(finding) == ["s 0x401000", "pdf @ 0x401000"]
    assert result["radare2_commands"] == ["s 0x401000", "pdf @ 0x401000"]


def test_explain_reads_offsets_from_evidence() -> None:
    finding = (
        _report(["rule.one"])
        .findings[0]
        .model_copy(update={"locations": [], "evidence": [EvidenceV1(kind="offset", value=0x40)]})
    )
    assert radare2_commands(finding) == ["s 0x40", "pdf @ 0x40"]


def test_cluster_reports_groups_similar_finding_sets(tmp_path: Path) -> None:
    for name, rules in (
        ("a.json", ["one", "two"]),
        ("b.json", ["one", "two"]),
        ("c.json", ["other"]),
    ):
        (tmp_path / name).write_text(_report(rules).model_dump_json(), encoding="utf-8")
    clusters = cluster_reports([tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"])
    assert [len(cluster) for cluster in clusters] == [2, 1]


def test_cluster_reports_uses_similarity_hashes(tmp_path: Path) -> None:
    sample = SampleInfoV1(size=1, hashes={"imphash": "abc"})
    left = _report([]).model_copy(update={"sample": sample})
    right = _report([]).model_copy(update={"sample": sample})
    (tmp_path / "left.json").write_text(left.model_dump_json(), encoding="utf-8")
    (tmp_path / "right.json").write_text(right.model_dump_json(), encoding="utf-8")
    assert len(cluster_reports([tmp_path / "left.json", tmp_path / "right.json"], 0.5)) == 1


def test_similarity_index_persists_and_queries_by_sha256(tmp_path: Path) -> None:
    paths = [tmp_path / "left.json", tmp_path / "right.json"]
    for path, digest in zip(paths, ("a" * 64, "b" * 64), strict=True):
        report = _report(["same.rule"]).model_copy(
            update={"sample": SampleInfoV1(size=1, hashes={"sha256": digest})}
        )
        path.write_text(report.model_dump_json(), encoding="utf-8")

    database = tmp_path / "similarity.sqlite3"
    assert index_reports(paths, database) == 2
    assert query_index(database, "a" * 64) == [
        {"sha256": "b" * 64, "report_path": str(paths[1]), "similarity": 1.0}
    ]


def test_clustering_threshold_is_calibrated_from_labeled_pairs(tmp_path: Path) -> None:
    cases = []
    for name, cluster, rules in (
        ("a", "family", ["shared"]),
        ("b", "family", ["shared"]),
        ("c", "other", ["different"]),
    ):
        report_path = tmp_path / f"{name}.json"
        report_path.write_text(_report(rules).model_dump_json(), encoding="utf-8")
        cases.append({"id": name, "cluster": cluster, "report": report_path.name})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"corpus_id": "test", "cases": cases}), encoding="utf-8")

    result = calibrate(manifest)
    assert result["threshold"] == 1.0
    assert result["precision"] == result["recall"] == result["f1"] == 1.0


def test_similarity_hashes_extracts_analyzer_results() -> None:
    assert similarity_hashes(
        {
            "ssdeep": {"hash_value": "3:abc:def"},
            "tlsh": {"binary_tlsh": "T123"},
            "simhash": {"combined_simhash": {"hex": "0x1234"}},
        }
    ) == {"ssdeep": "3:abc:def", "tlsh": "T123", "simhash": "0x1234"}


def test_similarity_handles_simhash_and_missing_report_identifiers(tmp_path: Path) -> None:
    assert feature_similarity(
        {"rule_ids": set(), "hashes": {"simhash": "0x0"}},
        {"rule_ids": set(), "hashes": {"simhash": "0x1"}},
    ) == pytest.approx(0.45)
    assert (
        feature_similarity(
            {"rule_ids": set(), "hashes": {"simhash": "invalid"}},
            {"rule_ids": set(), "hashes": {"simhash": "different"}},
        )
        == 0
    )

    report = tmp_path / "missing-sha.json"
    report.write_text(_report([]).model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="no sample SHA-256"):
        index_reports([report], tmp_path / "index.sqlite3")


def test_similarity_uses_optional_native_comparators(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = {
        "ssdeep": SimpleNamespace(compare=lambda _left, _right: 50),
        "tlsh": SimpleNamespace(diff=lambda _left, _right: 60),
    }
    monkeypatch.setattr(report_similarity.importlib, "import_module", modules.__getitem__)
    assert (
        feature_similarity(
            {"rule_ids": set(), "hashes": {"ssdeep": "left"}},
            {"rule_ids": set(), "hashes": {"ssdeep": "right"}},
        )
        == 0.3
    )
    assert feature_similarity(
        {"rule_ids": set(), "hashes": {"tlsh": "left"}},
        {"rule_ids": set(), "hashes": {"tlsh": "right"}},
    ) == pytest.approx(0.48)
    monkeypatch.setattr(
        report_similarity.importlib,
        "import_module",
        lambda _name: (_ for _ in ()).throw(ImportError()),
    )
    assert (
        feature_similarity(
            {"rule_ids": set(), "hashes": {"impfuzzy": "left"}},
            {"rule_ids": set(), "hashes": {"impfuzzy": "right"}},
        )
        == 0
    )


def test_clustering_cli_indexes_queries_and_validates_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(["same.rule"]).model_copy(
        update={"sample": SampleInfoV1(size=1, hashes={"sha256": "a" * 64})}
    )
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    database = tmp_path / "index.sqlite3"

    monkeypatch.setattr(sys, "argv", ["cluster", str(path), "--index", str(database)])
    clustering.cluster_main()
    assert json.loads(capsys.readouterr().out)[0][0]["sample"] == "a" * 64

    monkeypatch.setattr(sys, "argv", ["cluster", "--index", str(database), "--query", "a" * 64])
    clustering.cluster_main()
    assert json.loads(capsys.readouterr().out) == []

    for argv, message in (
        (["cluster", "--threshold", "2"], "threshold must be between 0 and 1"),
        (["cluster", "--query", "missing"], "--query requires --index"),
        (["cluster"], "at least one report is required"),
    ):
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit, match=message):
            clustering.cluster_main()


def test_verify_signed_rule_pack(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yar"
    rule.write_text("rule test { condition: true }", encoding="utf-8")
    private = Ed25519PrivateKey.generate()
    payload = {
        "pack_id": "local",
        "version": "1.0.0",
        "files": {"rule.yar": hashlib.sha256(rule.read_bytes()).hexdigest()},
    }
    manifest = RulePackManifest("local", "1.0.0", payload["files"])
    signed = base64.b64encode(private.sign(manifest.signing_payload())).decode()
    (tmp_path / "manifest.json").write_text(
        json.dumps({**payload, "signature": signed}), encoding="utf-8"
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert verify_rule_pack(tmp_path, public_key=public).version == "1.0.0"
