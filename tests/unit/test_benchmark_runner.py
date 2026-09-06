from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.run_corpus import _load_manifest, _sha256, run_corpus, validate_release_manifest


def test_load_manifest_requires_cases(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="non-empty cases"):
        _load_manifest(manifest)


def test_run_corpus_rejects_fixture_hash_mismatch(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "sample.bin").write_bytes(b"fixture")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "sample",
                        "sample": "sample.bin",
                        "sha256": "0" * 64,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert _sha256(corpus / "sample.bin") != "0" * 64
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        run_corpus(manifest, corpus, tmp_path / "out")


def test_real_manifest_requires_evaluation_role_and_sample_taxonomy(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    base = {
        "corpus_kind": "real_labeled",
        "provenance": {
            "source": "source",
            "dataset_version": "v1",
            "labeling_method": "review",
        },
        "cases": [
            {
                "sample": "sample.bin",
                "sha256": "a" * 64,
                "class": "benign",
                "sample_type": "benignware",
            }
        ],
    }
    manifest.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(ValueError, match="evaluation_role"):
        _load_manifest(manifest)

    base["evaluation_role"] = "holdout"
    base["cases"][0]["sample_type"] = "unclassified"
    manifest.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(ValueError, match="sample_type"):
        _load_manifest(manifest)


def test_release_manifest_requires_large_labeled_holdout() -> None:
    cases = [
        {
            "sample": f"{label}-{index}.bin",
            "sha256": "a" * 64,
            "class": label,
            "sample_type": "benignware" if label == "benign" else "malware",
            "expected_findings": (
                [{"rule_id": "rule.malware", "category": "malware"}]
                if label == "malware" and index == 0
                else []
            ),
        }
        for label in ("benign", "malware")
        for index in range(100)
    ]
    manifest = {
        "corpus_kind": "real_labeled",
        "evaluation_role": "holdout",
        "cases": cases,
    }

    validate_release_manifest(manifest)

    manifest["evaluation_role"] = "calibration"
    with pytest.raises(ValueError, match="independent holdout"):
        validate_release_manifest(manifest)
    manifest["evaluation_role"] = "holdout"

    removed = cases.pop()
    with pytest.raises(ValueError, match="100 benign and 100 malware"):
        validate_release_manifest(manifest)
    cases.append(removed)

    del cases[0]["expected_findings"]
    with pytest.raises(ValueError, match="structured expected_findings"):
        validate_release_manifest(manifest)
