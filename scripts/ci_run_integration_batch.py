#!/usr/bin/env python3
"""Run integration tests in parallel batches.

This script divides integration tests into batches for parallel execution.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def get_test_files(tests_dir: Path) -> list[Path]:
    """Get all integration test files."""
    return sorted(tests_dir.glob("test_*.py"))


def divide_into_batches(files: list[Path], num_batches: int) -> list[list[Path]]:
    """Divide files into N batches."""
    batches = [[] for _ in range(num_batches)]
    for i, file in enumerate(files):
        batches[i % num_batches].append(file)
    return batches


def run_batch(
    batch_files: list[Path],
    batch_num: int,
    total_batches: int,
    coverage_dir: Path,
    threshold: float,
) -> int:
    """Run a single batch of tests."""
    if not batch_files:
        print(f"Batch {batch_num}/{total_batches}: No files to test")
        return 0

    test_paths = [str(f) for f in batch_files]
    coverage_file = coverage_dir / f"coverage-batch-{batch_num}.json"

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *test_paths,
        "-q",
        "-m",
        "not slow",
        f"--cov=r2inspect",
        f"--cov-report=json:{coverage_file}",
        "--cov-report=term-missing",
        f"--cov-fail-under={threshold}",
    ]

    print(f"Batch {batch_num}/{total_batches}: Running {len(batch_files)} test files")
    print(f"  Files: {[f.name for f in batch_files[:5]]}{'...' if len(batch_files) > 5 else ''}")

    result = subprocess.run(cmd, capture_output=False)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run integration tests in batches")
    parser.add_argument(
        "--batch",
        type=int,
        required=True,
        help="Batch number (1-based)",
    )
    parser.add_argument(
        "--total-batches",
        type=int,
        required=True,
        help="Total number of batches",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=70.0,
        help="Coverage threshold",
    )
    parser.add_argument(
        "--tests-dir",
        type=str,
        default="tests/integration",
        help="Directory containing integration tests",
    )
    args = parser.parse_args()

    tests_dir = Path(args.tests_dir)
    if not tests_dir.exists():
        print(f"Tests directory not found: {tests_dir}")
        return 1

    coverage_dir = Path(".coverage-gate")
    coverage_dir.mkdir(parents=True, exist_ok=True)

    test_files = get_test_files(tests_dir)
    if not test_files:
        print(f"No test files found in {tests_dir}")
        return 1

    print(f"Found {len(test_files)} test files")
    batches = divide_into_batches(test_files, args.total_batches)

    if args.batch < 1 or args.batch > args.total_batches:
        print(f"Invalid batch number: {args.batch} (must be 1-{args.total_batches})")
        return 1

    batch_files = batches[args.batch - 1]
    return run_batch(
        batch_files,
        args.batch,
        args.total_batches,
        coverage_dir,
        args.threshold,
    )


if __name__ == "__main__":
    sys.exit(main())
