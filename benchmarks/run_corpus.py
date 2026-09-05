#!/usr/bin/env python3
"""Run report/v1 analysis for a pinned, independently labeled corpus."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import platform as platform_module
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

from r2inspect.schemas.report_v1 import ReportV1

_REAL_SAMPLE_TYPES = {
    "administrative_tool",
    "benignware",
    "malformed",
    "malware",
    "system_library",
    "unknown",
}

try:
    from benchmarks.differential_tools import TOOL_COMMANDS, compare_report, run_specialist_safe
except ModuleNotFoundError:  # direct ``python benchmarks/run_corpus.py`` execution
    from differential_tools import TOOL_COMMANDS, compare_report, run_specialist_safe


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    manifest = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a non-empty cases list")
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("sample"), str):
            raise ValueError("each corpus case requires a sample path")
    if manifest.get("corpus_kind") == "real_labeled":
        if manifest.get("evaluation_role") not in {"calibration", "holdout"}:
            raise ValueError("real_labeled corpora require calibration or holdout evaluation_role")
        provenance = manifest.get("provenance")
        if not isinstance(provenance, dict) or not all(
            isinstance(provenance.get(key), str) and provenance[key]
            for key in ("source", "dataset_version", "labeling_method")
        ):
            raise ValueError(
                "real_labeled corpora require source, version, and labeling provenance"
            )
        for case in cases:
            if case.get("class") not in {"benign", "malware", "unknown"}:
                raise ValueError("real_labeled cases require benign, malware, or unknown classes")
            if case.get("sample_type") not in _REAL_SAMPLE_TYPES:
                raise ValueError("real_labeled cases require a supported sample_type")
            digest = case.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("real_labeled cases require SHA-256 hashes")
    return manifest


def validate_release_manifest(manifest: dict[str, Any], *, minimum_per_class: int = 100) -> None:
    """Require an independently labeled holdout large enough for a stable release."""
    if manifest.get("corpus_kind") != "real_labeled":
        raise ValueError("release corpus must be real_labeled")
    if manifest.get("evaluation_role") != "holdout":
        raise ValueError("release corpus must be an independent holdout")
    cases = cast(list[dict[str, Any]], manifest["cases"])
    counts = {
        label: sum(case.get("class") == label for case in cases) for label in ("benign", "malware")
    }
    if any(count < minimum_per_class for count in counts.values()):
        raise ValueError(
            f"release corpus requires at least {minimum_per_class} benign and "
            f"{minimum_per_class} malware cases"
        )
    labels = [case.get("expected_findings") for case in cases]
    if not all(
        isinstance(expected, list)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("rule_id"), str)
            and isinstance(item.get("category"), str)
            for item in expected
        )
        for expected in labels
    ):
        raise ValueError("release corpus cases require structured expected_findings labels")
    if not any(labels):
        raise ValueError("release corpus must contain at least one expected finding")


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
    differential_tools: tuple[str, ...] = (),
    project_root: Path | None = None,
    release_gate: bool = False,
    workers: int = 1,
) -> Path:
    if workers < 1:
        raise ValueError("workers must be at least one")
    manifest = _load_manifest(manifest_path)
    if release_gate:
        validate_release_manifest(manifest)
    root = project_root or Path(__file__).resolve().parents[1]
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    selected_profile = profile or str(manifest.get("profile", "standard"))
    evaluated_cases: list[dict[str, Any]] = []
    differential: list[dict[str, Any]] = []
    differential_timeout = int(os.environ.get("R2INSPECT_DIFFERENTIAL_TIMEOUT_SECONDS", "120"))
    cases = manifest["cases"]
    if workers == 1:
        reports = [
            _run_case(case, corpus_dir, reports_dir, selected_profile, root) for case in cases
        ]
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            reports = list(
                executor.map(
                    lambda case: _run_case(case, corpus_dir, reports_dir, selected_profile, root),
                    cases,
                )
            )
    for case, report in zip(cases, reports, strict=True):
        evaluated_cases.append(
            {
                **case,
                "report": report,
                "runner_platform": sys.platform,
                "runner_os": platform_module.system(),
            }
        )
        if differential_tools:
            report_model = ReportV1.model_validate_json(
                (output_dir / report).read_text(encoding="utf-8")
            )
            for tool in differential_tools:
                observation = run_specialist_safe(
                    tool,
                    corpus_dir / str(case["sample"]),
                    timeout=differential_timeout,
                )
                findings = set(observation["findings"])
                differential.append(
                    {
                        "case": case["id"],
                        "tool": tool,
                        **observation,
                        **compare_report(report_model, findings, tool=tool),
                    }
                )

    evaluation_manifest = {
        "schema_version": manifest.get("schema_version", "r2inspect.benchmark/v1"),
        "corpus_kind": manifest.get("corpus_kind", "synthetic"),
        "corpus_id": manifest.get("corpus_id"),
        "evaluation_role": manifest.get("evaluation_role"),
        "provenance": manifest.get("provenance"),
        "fixture_repository": manifest.get("fixture_repository"),
        "fixture_commit": manifest.get("fixture_commit"),
        "fixture_repositories": manifest.get("fixture_repositories"),
        "fixture_commits": manifest.get("fixture_commits"),
        "classification": manifest.get("classification"),
        "profile": selected_profile,
        "runner_platform": sys.platform,
        "runner_os": platform_module.system(),
        "cases": evaluated_cases,
    }
    if differential:
        evaluation_manifest["differential"] = differential
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
    parser.add_argument("--profile", choices=("fast", "standard", "deep", "forensic"))
    parser.add_argument("--differential-tool", action="append", choices=tuple(TOOL_COMMANDS))
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--release-gate", action="store_true")
    args = parser.parse_args()
    run_corpus(
        args.manifest,
        args.corpus_dir,
        args.output_dir,
        profile=args.profile,
        differential_tools=tuple(args.differential_tool or ()),
        release_gate=args.release_gate,
        workers=args.workers,
    )


if __name__ == "__main__":
    main()
