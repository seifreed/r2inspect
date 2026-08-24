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
