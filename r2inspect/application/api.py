"""Small authenticated REST API for the persistent job queue."""

from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer
from pathlib import Path

from ..infrastructure.logging import flush_logging, get_logger, setup_logger
from .api_handler import build_handler
from .job_queue import JobQueue

logger = get_logger(__name__)


def create_server(
    database: Path,
    sample_root: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    token: str | None = None,
) -> ThreadingHTTPServer:
    """Create the REST server without starting its event loop."""
    if host not in {"127.0.0.1", "localhost", "::1"} and not token:
        raise ValueError("--token is required when listening outside localhost")
    root = sample_root.resolve()
    if not root.is_dir():
        raise ValueError(f"sample root is not a directory: {root}")
    return ThreadingHTTPServer((host, port), build_handler(JobQueue(database), root, token))


def main() -> None:
    setup_logger(thread_safe=True)
    parser = argparse.ArgumentParser(description="Serve the r2inspect analysis queue")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--sample-root", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--token", default=os.getenv("R2INSPECT_API_TOKEN"))
    args = parser.parse_args()
    try:
        server = create_server(
            args.database, args.sample_root, host=args.host, port=args.port, token=args.token
        )
    except ValueError as exc:
        logger.warning(
            "API configuration rejected",
            extra={"event_name": "api.configuration_rejected", "error_type": type(exc).__name__},
        )
        raise SystemExit(str(exc)) from exc
    host, port = server.server_address[:2]
    logger.info(
        "API server started",
        extra={
            "event_name": "api.started",
            "operation": "serve",
            "host": host,
            "port": port,
            "outcome": "ready",
        },
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("API shutdown requested", extra={"event_name": "api.shutdown_requested"})
    finally:
        server.server_close()
        logger.info("API server stopped", extra={"event_name": "api.stopped"})
        flush_logging()


__all__ = ["create_server", "main"]
