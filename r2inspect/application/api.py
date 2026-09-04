"""Small authenticated REST API for the persistent job queue."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .job_queue import JobQueue

MAX_REQUEST_BYTES = 16 * 1024
PROFILES = {"fast", "standard", "deep", "forensic"}


def _sample_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError("sample_path must be a relative path")
    path = (root / value).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("sample_path is outside the sample root or is not a file")
    return path


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
    queue = JobQueue(database)

    class Handler(BaseHTTPRequestHandler):
        server_version = "r2inspect-api/1"

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if token is None:
                return True
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if supplied and secrets.compare_digest(supplied, token):
                return True
            self._send(401, {"error": "unauthorized"})
            return False

        def do_GET(self) -> None:
            if not self._authorized():
                return
            path = urlparse(self.path).path
            if path == "/health":
                self._send(200, {"status": "ok"})
                return
            prefix = "/v1/jobs/"
            job = queue.get(path[len(prefix) :]) if path.startswith(prefix) else None
            self._send(200, job) if job else self._send(404, {"error": "job not found"})

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if urlparse(self.path).path != "/v1/jobs":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_REQUEST_BYTES:
                    raise ValueError("invalid request size")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("request body must be an object")
                profile = payload.get("profile", "standard")
                if profile not in PROFILES:
                    raise ValueError("invalid analysis profile")
                job = queue.enqueue(_sample_path(root, payload.get("sample_path")), profile)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(201, job)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
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
        raise SystemExit(str(exc)) from exc
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


__all__ = ["create_server", "main"]
