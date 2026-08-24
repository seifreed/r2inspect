#!/usr/bin/env python3
"""Run report/v1 analysis for a pinned, independently labeled corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from r2inspect.schemas.report_v1 import ReportV1


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a non-empty cases list")
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("sample"), str):
            raise ValueError("each corpus case requires a sample path")
    return manifest


def _run_case(
    case: dict[str, Any],
    corpus_dir: Path,
    reports_dir: Path,
    profile: str,
    project_root: Path,
) -> str:
    sample = corpus_dir / str(case["sample"])
    expected_hash = case.get("sha256")
    if not sample.is_file():
        raise FileNotFoundError(sample)
    if expected_hash and _sha256(sample) != expected_hash:
        raise ValueError(f"SHA-256 mismatch for {sample}")

    report_name = f"{case['id']}.json"
    report_path = reports_dir / report_name
    env = os.environ.copy()
    env.setdefault("R2INSPECT_CMD_TIMEOUT_SECONDS", "30")
    command = [
        sys.executable,
        "-m",
        "r2inspect",
        "--quiet",
        "--json",
        "--profile",
        profile,
        "--output",
        str(report_path),
        str(sample),
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=project_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"analysis failed for {case['id']}: {detail}")
    report = ReportV1.model_validate_json(report_path.read_text(encoding="utf-8"))
    if report.analysis.duration <= 0:
        report.analysis.duration = time.monotonic() - started
        report.metrics["benchmark_wall_time_seconds"] = report.analysis.duration
        report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return f"reports/{report_name}"


def run_corpus(
    manifest_path: Path,
    corpus_dir: Path,
    output_dir: Path,
    *,
    profile: str | None = None,
    project_root: Path | None = None,
) -> Path:
    manifest = _load_manifest(manifest_path)
    root = project_root or Path(__file__).resolve().parents[1]
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    selected_profile = profile or str(manifest.get("profile", "standard"))
    evaluated_cases: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        report = _run_case(case, corpus_dir, reports_dir, selected_profile, root)
        evaluated_cases.append({**case, "report": report})

    evaluation_manifest = {
        "schema_version": manifest.get("schema_version", "r2inspect.benchmark/v1"),
        "corpus_id": manifest.get("corpus_id"),
        "fixture_repository": manifest.get("fixture_repository"),
        "fixture_commit": manifest.get("fixture_commit"),
        "profile": selected_profile,
        "cases": evaluated_cases,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "manifest.json"
    result_path.write_text(
        json.dumps(evaluation_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", choices=("fast", "standard", "deep"))
    args = parser.parse_args()
    run_corpus(args.manifest, args.corpus_dir, args.output_dir, profile=args.profile)


if __name__ == "__main__":
    main()
