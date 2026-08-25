from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from r2inspect.application.clustering import cluster_reports
from r2inspect.application.explain import explain, radare2_commands
from r2inspect.application.rule_packs import RulePackManifest, verify_rule_pack
from r2inspect.schemas.report_v1 import EvidenceV1, FindingV1, LocationV1, ReportV1


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
