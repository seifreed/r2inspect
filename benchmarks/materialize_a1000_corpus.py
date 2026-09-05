#!/usr/bin/env python3
"""Materialize the pinned A1000 corpus without storing samples in Git."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

FIXTURE_COMMIT = "1d8a0ac76d92dfd68587ba30b1c987b78b59009a"
FIXTURE_BASE = (
    "https://raw.githubusercontent.com/seifreed/r2inspect-test-binaries/" f"{FIXTURE_COMMIT}/"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_url(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "r2inspect-a1000-corpus/1"})
    with urllib.request.urlopen(request, timeout=180) as response:
        destination.write_bytes(response.read())


def _download_a1000(hash_value: str, destination: Path) -> None:
    host = os.environ.get("A1000_HOST", "https://a1000.reversinglabs.com").rstrip("/")
    token = os.environ.get("A1000_TOKEN")
    if not token:
        raise RuntimeError("A1000_TOKEN is required to materialize A1000 samples")
    request = urllib.request.Request(
        f"{host}/api/samples/{hash_value}/download/",
        headers={"Authorization": f"Token {token}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        destination.write_bytes(response.read())


def _download_with_rl_cli(hash_value: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["rl-cli", "-q", "a1000", "download", "--output-dir", str(destination.parent), hash_value],
        check=True,
        timeout=300,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    downloaded = destination.parent / f"{hash_value}.malware"
    if downloaded != destination:
        shutil.move(downloaded, destination)


def materialize(manifest_path: Path, output_dir: Path, *, use_rl_cli: bool = False) -> Path:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain cases")
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("manifest cases must be objects")
        sample = output_dir / str(case["sample"])
        sample.parent.mkdir(parents=True, exist_ok=True)
        if not sample.is_file():
            if case.get("source") == "a1000":
                if use_rl_cli:
                    _download_with_rl_cli(str(case["sha256"]), sample)
                else:
                    _download_a1000(str(case["sha256"]), sample)
            elif case.get("source") == "fixture":
                _download_url(f"{FIXTURE_BASE}{case['fixture_path']}", sample)
            else:
                raise ValueError(f"unsupported sample source: {case.get('source')}")
        actual = _sha256(sample)
        if actual != case.get("sha256"):
            raise ValueError(f"SHA-256 mismatch for {case.get('id')}: {actual}")

    benchmark_dir = output_dir / "benchmark"
    benchmark_dir.mkdir(parents=True, exist_ok=True)
    target_manifest = benchmark_dir / "manifest.json"
    target_manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return target_manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rl-cli", action="store_true", help="Use rl-cli for A1000 downloads")
    args = parser.parse_args()
    print(materialize(args.manifest, args.output_dir, use_rl_cli=args.rl_cli))


if __name__ == "__main__":
    main()
