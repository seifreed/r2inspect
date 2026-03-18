"""Service/dependency wiring helpers for CLI batch processing."""

from __future__ import annotations

import time
from typing import Any

from ..application.batch_models import BatchDependencies


def build_batch_dependencies(
    *,
    find_files_to_process: Any,
    setup_rate_limiter: Any,
    process_files_parallel: Any,
) -> BatchDependencies:
    return BatchDependencies(
        find_files_to_process=find_files_to_process,
        setup_rate_limiter=setup_rate_limiter,
        process_files_parallel=process_files_parallel,
        now=time.time,
    )


def build_batch_service_facade(default_batch_service: Any, deps: BatchDependencies) -> Any:
    return type(
        "BatchServiceFacade",
        (),
        {
            "run_batch_analysis": lambda _self, **kwargs: default_batch_service.run_batch_analysis(
                **(kwargs | {"deps": deps})
            )
        },
    )()
