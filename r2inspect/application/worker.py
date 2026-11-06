"""Worker for queued r2inspect analysis jobs."""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import Config
from ..factory import create_inspector
from ..infrastructure.logging import (
    bind_log_context,
    flush_logging,
    get_logger,
    setup_logger,
)
from .job_queue import JobQueue
from .options import build_analysis_options
from .report_builder import report_payload_v1
from .use_cases import AnalyzeBinaryUseCase

logger = get_logger(__name__)


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
    started = time.perf_counter()
    with bind_log_context(
        correlation_id=job["id"],
        job_id=job["id"],
        operation="process_job",
    ):
        try:
            root = sample_root.resolve()
            sample = Path(job["sample_path"]).resolve()
            if not sample.is_relative_to(root) or not sample.is_file():
                raise ValueError("queued sample is outside the sample root or is not a file")
            queue.complete(job["id"], analyze(sample, job["profile"]))
        except Exception as exc:
            queue.fail(job["id"], str(exc))
            logger.exception(
                "Analysis job failed",
                extra={
                    "event_name": "job.failed",
                    "profile": job["profile"],
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "failed",
                },
            )
        else:
            logger.info(
                "Analysis job completed",
                extra={
                    "event_name": "job.completed",
                    "profile": job["profile"],
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "success",
                },
            )
    return True


def main() -> None:
    setup_logger(thread_safe=True)
    parser = argparse.ArgumentParser(description="Process r2inspect analysis jobs")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--sample-root", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    args = parser.parse_args()
    if args.poll_interval <= 0:
        logger.warning(
            "Worker configuration rejected",
            extra={
                "event_name": "worker.configuration_rejected",
                "error_code": "invalid_poll_interval",
            },
        )
        raise SystemExit("--poll-interval must be positive")
    queue = JobQueue(args.database)
    logger.info(
        "Worker started",
        extra={
            "event_name": "worker.started",
            "operation": "poll_jobs",
            "poll_interval": args.poll_interval,
            "outcome": "ready",
        },
    )
    try:
        while True:
            processed = process_next_job(queue, args.sample_root)
            if args.once:
                return
            if not processed:
                time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        logger.info("Worker shutdown requested", extra={"event_name": "worker.shutdown_requested"})
    finally:
        logger.info("Worker stopped", extra={"event_name": "worker.stopped"})
        flush_logging()


__all__ = ["main", "process_next_job"]
