#!/usr/bin/env python3
"""Fetch a small, pinned real corpus without storing samples in the repository."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

DATASET = "mandiant/capa-testfiles"
DATASET_COMMIT = "4fa9a0448a1453a80bdcbcefb6dff870f6333b64"
DATASET_URL = f"https://github.com/{DATASET}/tree/{DATASET_COMMIT}"
FIXTURE_DATASET = "seifreed/r2inspect-test-binaries"
FIXTURE_COMMIT = "1d8a0ac76d92dfd68587ba30b1c987b78b59009a"
FIXTURE_URL = f"https://github.com/{FIXTURE_DATASET}/tree/{FIXTURE_COMMIT}"

_SOURCE_BASES = {
    "capa": f"https://raw.githubusercontent.com/{DATASET}/{DATASET_COMMIT}/",
    "fixtures": f"https://raw.githubusercontent.com/{FIXTURE_DATASET}/{FIXTURE_COMMIT}/",
}

_SAMPLES = (
    (
        "pma_01_01_dll",
        "Practical Malware Analysis Lab 01-01.dll_",
        "malware",
        "f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba",
        "capa",
    ),
    (
        "pma_01_01_exe",
        "Practical Malware Analysis Lab 01-01.exe_",
        "malware",
        "58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47",
        "capa",
    ),
    (
        "pma_01_02_exe",
        "Practical Malware Analysis Lab 01-02.exe_",
        "malware",
        "c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6",
        "capa",
    ),
    (
        "pma_01_04_exe",
        "Practical Malware Analysis Lab 01-04.exe_",
        "malware",
        "0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126",
        "capa",
    ),
    (
        "pma_03_02_dll",
        "Practical Malware Analysis Lab 03-02.dll_",
        "malware",
        "5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9",
        "capa",
    ),
    (
        "pma_03_03_exe",
        "Practical Malware Analysis Lab 03-03.exe_",
        "malware",
        "ae8a1c7eb64c42ea2a04f97523ebf0844c27029eb040d910048b680f884b9dce",
        "capa",
    ),
    (
        "pma_03_04_exe",
        "Practical Malware Analysis Lab 03-04.exe_",
        "malware",
        "6ac06dfa543dca43327d55a61d0aaed25f3c90cce791e0555e3e306d47107859",
        "capa",
    ),
    (
        "pma_05_01_dll",
        "Practical Malware Analysis Lab 05-01.dll_",
        "malware",
        "eb1079bdd96bc9cc19c38b76342113a09666aad47518ff1a7536eebff8aadb4a",
        "capa",
    ),
    (
        "kernel32_x86",
        "kernel32.dll_",
        "benign",
        "3f94f8630c7603f9da79bf021cb56ac5357502badf6cb12f6ce11e5b2b244153",
        "capa",
    ),
    (
        "kernel32_x64",
        "kernel32-64.dll_",
        "benign",
        "7d148e220040de2fae1439fbc0e783ef344dceaea4757611722d8378a4938d0b",
        "capa",
    ),
    (
        "microsocks_elf",
        "microsocks.elf_",
        "benign",
        "4f405550ba8ce619bf5a3547acb7871009d1e51160d4feabdb3b7d827b44e507",
        "capa",
    ),
    (
        "hello_pe_benign",
        "pe/hello_pe.exe",
        "benign",
        "b4b674b6ede0cd5d4dcff2cff31a5957ac022ab995da977c667ddc7626205aea",
        "fixtures",
    ),
    (
        "hello_elf_benign",
        "elf/hello_elf",
        "benign",
        "39688c91f985915d521bd21983f600817507de4a70cde683ea372eb8472a3a09",
        "fixtures",
    ),
    (
        "hello_macho_benign",
        "mach0/hello_macho",
        "benign",
        "ccee249906bc711fae5d2cce11a3420e5598d71b10efa89c954e459905566357",
        "fixtures",
    ),
    (
        "hello_macho_stripped_benign",
        "mach0/hello_macho_stripped",
        "benign",
        "df350f6cb624bf5a9510e29693cc0142dbd4cfc3bbd0b9eccb9c49def29286ec",
        "fixtures",
    ),
    (
        "edge_high_entropy_benign",
        "edge/edge_high_entropy.bin",
        "benign",
        "9053b0f9ae54e451e48aae2a391f6ba9132475e4665faa39a84abcd4c3b13ee1",
        "fixtures",
    ),
    (
        "edge_packed_unknown",
        "edge/edge_packed.bin",
        "unknown",
        "aa91ef5653e4c6782ec48e0dec950e8e30cd5ca04c55feeb2ceb2c3ad175fee6",
        "fixtures",
    ),
    (
        "edge_bad_pe_unknown",
        "edge/edge_bad_pe.bin",
        "unknown",
        "10162bac44ed65caf0b4b8cb1dd6ff78522719e3d26580d9f0c63debeefd44c1",
        "fixtures",
    ),
    (
        "edge_tiny_unknown",
        "edge/edge_tiny.bin",
        "unknown",
        "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        "fixtures",
    ),
)

_SAMPLE_TYPE_OVERRIDES = {
    "kernel32_x86": "system_library",
    "kernel32_x64": "system_library",
    "microsocks_elf": "administrative_tool",
    "edge_packed_unknown": "unknown",
    "edge_bad_pe_unknown": "malformed",
    "edge_tiny_unknown": "malformed",
}


def _sample_type(case_id: str, label: str) -> str:
    return _SAMPLE_TYPE_OVERRIDES.get(case_id, "malware" if label == "malware" else "benignware")


def _manifest() -> dict[str, object]:
    return {
        "schema_version": "r2inspect.benchmark/v1",
        "corpus_kind": "real_labeled",
        "corpus_id": "capa-testfiles-pma-kernel32-fixtures-v3",
        "evaluation_role": "calibration",
        "provenance": {
            "source": DATASET_URL,
            "dataset_version": DATASET_COMMIT,
            "additional_source": FIXTURE_URL,
            "additional_dataset_version": FIXTURE_COMMIT,
            "labeling_method": "upstream sample provenance plus independently maintained synthetic fixture labels",
        },
        "fixture_repositories": [
            f"https://github.com/{DATASET}.git",
            f"https://github.com/{FIXTURE_DATASET}.git",
        ],
        "fixture_commits": [DATASET_COMMIT, FIXTURE_COMMIT],
        "profile": "forensic",
        "classification": {
            "strategy": "calibrated_behavior",
            "max_functions": 1000,
            "max_imports": 500,
            "max_exports": 500,
            "detection_analyzers": ["anti_analysis", "packer_detector", "yara_analyzer"],
        },
        "cases": [
            {
                "id": case_id,
                "sample": f"samples/{case_id}.bin",
                "sha256": digest,
                "class": label,
                "sample_type": _sample_type(case_id, label),
            }
            for case_id, _source_name, label, digest, _source in _SAMPLES
        ],
    }


def _download(source_name: str, destination: Path, source: str) -> None:
    url = f"{_SOURCE_BASES[source]}{quote(source_name)}"
    request = Request(url, headers={"User-Agent": "r2inspect-real-corpus/1"})
    with urlopen(request, timeout=120) as response:
        data = response.read()
    destination.write_bytes(data)


def fetch(output_dir: Path) -> Path:
    samples_dir = output_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    for case_id, source_name, _label, expected_digest, source in _SAMPLES:
        destination = samples_dir / f"{case_id}.bin"
        _download(source_name, destination, source)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        if digest != expected_digest:
            raise ValueError(f"SHA-256 mismatch for {source_name}: {digest}")
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest(), indent=2) + "\n", encoding="utf-8")
    return manifest_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    print(fetch(args.output_dir))


if __name__ == "__main__":
    main()
