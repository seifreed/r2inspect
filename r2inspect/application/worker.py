"""Worker for queued r2inspect analysis jobs."""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import Config
from ..factory import create_inspector
from .job_queue import JobQueue
from .options import build_analysis_options
from .report_builder import report_payload_v1
from .use_cases import AnalyzeBinaryUseCase


def _analyze(sample: Path, profile: str) -> dict[str, Any]:
    options = build_analysis_options(None, None, profile)
    with create_inspector(filename=str(sample), config=Config(), verbose=False) as inspector:
        result = AnalyzeBinaryUseCase().run(inspector, options)
    return report_payload_v1(result, options)


def process_next_job(
    queue: JobQueue,
    sample_root: Path,
    *,
    analyze: Callable[[Path, str], dict[str, Any]] = _analyze,
) -> bool:
    """Claim and process one job; return false when the queue is empty."""
    job = queue.claim()
    if job is None:
        return False
    try:
        root = sample_root.resolve()
        sample = Path(job["sample_path"]).resolve()
        if not sample.is_relative_to(root) or not sample.is_file():
            raise ValueError("queued sample is outside the sample root or is not a file")
        queue.complete(job["id"], analyze(sample, job["profile"]))
    except Exception as exc:
        queue.fail(job["id"], str(exc))
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Process r2inspect analysis jobs")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--sample-root", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    args = parser.parse_args()
    if args.poll_interval <= 0:
        raise SystemExit("--poll-interval must be positive")
    queue = JobQueue(args.database)
    try:
        while True:
            processed = process_next_job(queue, args.sample_root)
            if args.once:
                return
            if not processed:
                time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        return


__all__ = ["main", "process_next_job"]
