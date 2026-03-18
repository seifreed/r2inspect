#!/usr/bin/env python3
"""Run integration coverage gate in shards and merge into a fresh global report."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

PRIORITY_MAP: dict[str, str] = {
    "r2inspect/cli_main.py": "A",
    "r2inspect/cli/validators.py": "A",
    "r2inspect/compat/command_helpers.py": "A",
    "r2inspect/compat/error_handler.py": "A",
    "r2inspect/compat/r2_helpers.py": "A",
    "r2inspect/compat/r2_session.py": "A",
    "r2inspect/adapters/r2_commands.py": "A",
    "r2inspect/utils/circuit_breaker.py": "A",
    "r2inspect/cli/commands/analyze_command.py": "B",
    "r2inspect/cli/commands/config_command.py": "B",
    "r2inspect/cli/commands/batch_command.py": "B",
    "r2inspect/cli/commands/interactive_command.py": "B",
    "r2inspect/cli/batch_output.py": "B",
    "r2inspect/cli/display_sections_metadata.py": "B",
    "r2inspect/cli/display_sections_similarity.py": "B",
    "r2inspect/registry/metadata_extraction.py": "C",
    "r2inspect/registry/registry_queries.py": "C",
    "r2inspect/schemas/results_loader.py": "C",
    "r2inspect/schemas/converters.py": "C",
    "r2inspect/utils/memory_manager.py": "D",
    "r2inspect/utils/retry_manager.py": "D",
    "r2inspect/utils/rate_limiter.py": "D",
}

PHASE_LABELS = {
    "A": "Fase A — base/compat/r2",
    "B": "Fase B — cli/ux",
    "C": "Fase C — registry/schemas",
    "D": "Fase D — resiliencia",
}
PHASE_PRIORITY = ["A", "B", "C", "D"]
REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = REPO_ROOT / ".coverage-gate"
SAMPLES_DIR = REPO_ROOT / "samples" / "fixtures"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run sharded integration tests and merge coverage into a fresh global report."
    )
    parser.add_argument(
        "--threshold", type=float, default=95.0, help="Coverage threshold in percent."
    )
    parser.add_argument(
        "--shards", type=int, default=4, help="Number of shards to split integration tests."
    )
    parser.add_argument(
        "--max-modules", type=int, default=200, help="Max number of low-covered modules to print."
    )
    parser.add_argument(
        "--shard-timeout-seconds",
        type=int,
        default=900,
        help="Max seconds to wait for each shard process before forcing termination.",
    )
    parser.add_argument(
        "--coverage-json",
        default=".coverage-gate/coverage-integration.json",
        help="Merged coverage JSON output path.",
    )
    parser.add_argument(
        "--coverage-xml",
        default=".coverage-gate/coverage-integration.xml",
        help="Merged coverage XML output path.",
    )
    parser.add_argument(
        "--output",
        default=".coverage-gate/low_coverage_modules.json",
        help="Path to write low coverage module ranking JSON.",
    )
    parser.add_argument(
        "--notes-path", default="coverage-notes.md", help="Path to append summary notes."
    )
    parser.add_argument(
        "--append-notes", action="store_true", help="Append run summary to notes file."
    )
    return parser.parse_args()


def _module_priority(path: str) -> tuple[int, str]:
    phase = PRIORITY_MAP.get(path)
    if phase is None:
        return len(PHASE_PRIORITY), "Z"
    return PHASE_PRIORITY.index(phase), phase


def _resolve_binary_source_root() -> Path | None:
    configured = os.getenv("R2INSPECT_TEST_BINARIES_DIR", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    candidates.append(REPO_ROOT.parent / "r2inspect-test-binaries")
    candidates.append(SAMPLES_DIR)
    for path in candidates:
        if path.exists():
            return path
    return None


def _detect_format(data: bytes) -> str:
    head = data[:4]
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return "MACHO"
    return "Unknown"


def _expected_payload(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    file_format = _detect_format(data)
    return {
        "file_format": file_format,
        "name": path.name,
        "size": path.stat().st_size,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "file_info": {
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "file_type": file_format,
        },
        "hashing": {},
        "security": {},
    }


def _ensure_legacy_samples_tree() -> None:
    source_root = _resolve_binary_source_root()
    if source_root is None:
        raise FileNotFoundError(
            "No fixture binaries source found. Set R2INSPECT_TEST_BINARIES_DIR or provide ../r2inspect-test-binaries."
        )

    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    if (source_root / "hello_pe.exe").exists():
        mapping = {
            "hello_pe.exe": source_root / "hello_pe.exe",
            "hello_elf": source_root / "hello_elf",
            "hello_macho": source_root / "hello_macho",
            "hello_macho_stripped": source_root / "hello_macho_stripped",
            "edge_tiny.bin": source_root / "edge_tiny.bin",
            "edge_packed.bin": source_root / "edge_packed.bin",
            "edge_bad_pe.bin": source_root / "edge_bad_pe.bin",
            "edge_high_entropy.bin": source_root / "edge_high_entropy.bin",
        }
    else:
        mapping = {
            "hello_pe.exe": source_root / "pe" / "hello_pe.exe",
            "hello_elf": source_root / "elf" / "hello_elf",
            "hello_macho": source_root / "mach0" / "hello_macho",
            "hello_macho_stripped": source_root / "mach0" / "hello_macho_stripped",
            "edge_tiny.bin": source_root / "edge" / "edge_tiny.bin",
            "edge_packed.bin": source_root / "edge" / "edge_packed.bin",
            "edge_bad_pe.bin": source_root / "edge" / "edge_bad_pe.bin",
            "edge_high_entropy.bin": source_root / "edge" / "edge_high_entropy.bin",
        }

    for target_name, src in mapping.items():
        if not src.exists():
            continue
        dst = SAMPLES_DIR / target_name
        if dst.exists():
            continue
        try:
            dst.symlink_to(src)
        except OSError:
            dst.write_bytes(src.read_bytes())

    expected_dir = SAMPLES_DIR / "expected"
    expected_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "hello_pe.exe",
        "hello_elf",
        "hello_macho",
        "edge_packed.bin",
        "edge_tiny.bin",
        "edge_bad_pe.bin",
        "edge_high_entropy.bin",
    ):
        fixture_path = SAMPLES_DIR / name
        if not fixture_path.exists():
            continue
        out_name = name.replace(".exe", "").replace(".bin", "") + ".json"
        (expected_dir / out_name).write_text(
            json.dumps(_expected_payload(fixture_path), indent=2),
            encoding="utf-8",
        )


def _clean_old_artifacts() -> None:
    for path in ARTIFACTS_DIR.glob(".coverage.shard*"):
        path.unlink(missing_ok=True)
    for name in (
        "coverage-integration.json",
        "coverage-integration.xml",
        "low_coverage_modules.json",
        "integration.junit.xml",
    ):
        (ARTIFACTS_DIR / name).unlink(missing_ok=True)
    for path in ARTIFACTS_DIR.glob("integration.shard*.junit.xml"):
        path.unlink(missing_ok=True)
    (REPO_ROOT / ".coverage").unlink(missing_ok=True)


def _discover_integration_tests() -> list[Path]:
    return sorted((REPO_ROOT / "tests" / "integration").glob("test_*.py"))


def _split_shards(files: list[Path], shards: int) -> list[list[Path]]:
    shard_lists: list[list[Path]] = [[] for _ in range(shards)]
    for index, path in enumerate(files):
        shard_lists[index % shards].append(path)
    return [items for items in shard_lists if items]


def _run_shard(shard_index: int, shard_files: list[Path], timeout_seconds: int) -> int:
    cov_file = ARTIFACTS_DIR / f".coverage.shard{shard_index}"
    junit_path = ARTIFACTS_DIR / f"integration.shard{shard_index}.junit.xml"

    env = dict(os.environ)
    env["COVERAGE_FILE"] = str(cov_file)
    env["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    env["R2INSPECT_TEST_SAFE_EXIT"] = "1"

    command: list[str] = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-m",
        "not slow",
        "--cov=r2inspect",
        "--cov-report=",
        f"--junitxml={junit_path}",
    ]
    command.extend(str(path.relative_to(REPO_ROOT)) for path in shard_files)
    print(f"[ci-shard] Running shard {shard_index} with {len(shard_files)} files")
    try:
        result = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            timeout=max(1, timeout_seconds),
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        print(
            f"[ci-shard] Timeout on shard {shard_index} after {timeout_seconds}s. "
            "Proceeding with available coverage data."
        )
        return 124


def _merge_coverage(coverage_json: Path, coverage_xml: Path) -> None:
    pattern = str(ARTIFACTS_DIR / ".coverage.shard*")
    coverage_files = sorted(glob.glob(pattern))
    if not coverage_files:
        raise FileNotFoundError("No shard coverage files found for merge.")

    combine_cmd = [sys.executable, "-m", "coverage", "combine"] + coverage_files
    subprocess.run(combine_cmd, cwd=REPO_ROOT, check=True)

    json_cmd = [sys.executable, "-m", "coverage", "json", "-o", str(coverage_json)]
    xml_cmd = [sys.executable, "-m", "coverage", "xml", "-o", str(coverage_xml)]
    report_cmd = [sys.executable, "-m", "coverage", "report", "-m"]
    subprocess.run(json_cmd, cwd=REPO_ROOT, check=True)
    subprocess.run(xml_cmd, cwd=REPO_ROOT, check=True)
    subprocess.run(report_cmd, cwd=REPO_ROOT, check=True)


def _load_coverage(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"coverage json not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_below_threshold(data: dict, threshold: float, max_modules: int) -> list[dict]:
    files = data.get("files", {})
    low: list[dict] = []
    for path, info in files.items():
        if not path.startswith("r2inspect/"):
            continue
        summary = info.get("summary", {})
        coverage = float(summary.get("percent_covered", 100.0) or 0.0)
        if coverage < threshold:
            phase_rank, phase_code = _module_priority(path)
            low.append(
                {
                    "path": path,
                    "coverage": coverage,
                    "phase": phase_code,
                    "priority": phase_rank,
                }
            )
    low.sort(key=lambda item: (item["priority"], item["coverage"], item["path"]))
    return low[:max_modules]


def _write_low_modules(
    path: Path, total: float | None, threshold: float, modules: list[dict]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "threshold": threshold,
                "total_coverage": total,
                "modules": modules,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _append_notes(
    notes_path: Path,
    threshold: float,
    total: float | None,
    shard_statuses: list[int],
    modules: list[dict],
) -> None:
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    total_display = "N/A" if total is None else f"{total:.2f}%"
    status = (
        "PASS"
        if all(code == 0 for code in shard_statuses) and (total or 0.0) >= threshold
        else "FAIL"
    )
    entry = [
        "",
        f"### Sharded Gate run {now}",
        "",
        "| Campo | Valor |",
        "| - | - |",
        f"| Umbral | {threshold}% |",
        f"| Estado | {status} |",
        f"| Cobertura total | {total_display} |",
        f"| Shards | {len(shard_statuses)} ({', '.join(str(s) for s in shard_statuses)}) |",
        f"| Módulos < umbral | {len(modules)} |",
    ]
    if modules:
        entry.extend(
            [
                "",
                "| Ruta | Cobertura | Fase |",
                "| - | -: | - |",
            ]
        )
        for row in modules[:20]:
            entry.append(f"| {row['path']} | {row['coverage']:.2f}% | {row['phase']} |")

    notes_path.parent.mkdir(parents=True, exist_ok=True)
    with notes_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(entry) + "\n")


def main() -> int:
    args = _parse_args()
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    _clean_old_artifacts()
    _ensure_legacy_samples_tree()

    test_files = _discover_integration_tests()
    shard_groups = _split_shards(test_files, max(1, args.shards))
    shard_statuses = [
        _run_shard(index + 1, shard, args.shard_timeout_seconds)
        for index, shard in enumerate(shard_groups)
    ]

    coverage_json = Path(args.coverage_json)
    coverage_xml = Path(args.coverage_xml)
    if not coverage_json.is_absolute():
        coverage_json = REPO_ROOT / coverage_json
    if not coverage_xml.is_absolute():
        coverage_xml = REPO_ROOT / coverage_xml

    _merge_coverage(coverage_json, coverage_xml)
    coverage_data = _load_coverage(coverage_json)
    total = coverage_data.get("totals", {}).get("percent_covered")
    below = _extract_below_threshold(coverage_data, args.threshold, args.max_modules)

    print()
    print("=" * 80)
    print(
        f"[ci-shard] Coverage total: {total:.2f}%"
        if total is not None
        else "[ci-shard] Coverage total: N/A"
    )
    print(f"[ci-shard] Threshold: {args.threshold}%")
    if below:
        print(f"[ci-shard] Modules below {args.threshold}%:")
        for index, row in enumerate(below, start=1):
            phase_label = PHASE_LABELS.get(row["phase"], "Unprioritized")
            print(
                f"[ci-shard] {index:>3}. {row['path']:<52} {row['coverage']:>6.2f}% "
                f"[phase={row['phase']}] ({phase_label})"
            )
    else:
        print("[ci-shard] No modules below threshold.")

    output = Path(args.output)
    if not output.is_absolute():
        output = REPO_ROOT / output
    _write_low_modules(output, total, args.threshold, below)

    if args.append_notes:
        notes_path = Path(args.notes_path)
        if not notes_path.is_absolute():
            notes_path = REPO_ROOT / notes_path
        _append_notes(notes_path, args.threshold, total, shard_statuses, below)

    failed_shards = any(code != 0 for code in shard_statuses)
    threshold_failed = total is None or total < args.threshold
    return 1 if failed_shards or threshold_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
