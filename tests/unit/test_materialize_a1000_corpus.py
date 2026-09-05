from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.materialize_a1000_corpus import materialize


def test_materialize_downloads_and_verifies_fixture(tmp_path: Path, monkeypatch) -> None:
    payload = b"fixture"
    digest = hashlib.sha256(payload).hexdigest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "corpus_kind": "real_labeled",
                "cases": [
                    {
                        "id": "fixture-1",
                        "source": "fixture",
                        "fixture_path": "pe/hello_pe.exe",
                        "sample": "samples/fixture.bin",
                        "sha256": digest,
                        "class": "benign",
                        "expected_findings": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_download(_url: str, destination: Path) -> None:
        destination.write_bytes(payload)

    monkeypatch.setattr("benchmarks.materialize_a1000_corpus._download_url", fake_download)

    result = materialize(manifest_path, tmp_path / "corpus")

    assert result == tmp_path / "corpus/benchmark/manifest.json"
    assert (tmp_path / "corpus/samples/fixture.bin").read_bytes() == payload
