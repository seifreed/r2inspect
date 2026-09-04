from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.run_corpus import _load_manifest, _sha256, run_corpus


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
