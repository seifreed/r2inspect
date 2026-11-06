"""Authenticated request handler for the local analysis queue API."""

from __future__ import annotations

import json
import secrets
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..infrastructure.logging import get_logger
from .api_observability import observed_request
from .job_queue import JobQueue

MAX_REQUEST_BYTES = 16 * 1024
PROFILES = {"fast", "standard", "deep", "forensic"}
logger = get_logger(__name__)


def sample_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError("sample_path must be a relative path")
    path = (root / value).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("sample_path is outside the sample root or is not a file")
    return path


def build_handler(queue: JobQueue, root: Path, token: str | None) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "r2inspect-api/1"
        _response_status = 0
        _request_id = ""

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            self._response_status = status
            body = json.dumps(payload, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if self._request_id:
                self.send_header("X-Request-ID", self._request_id)
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if token is None:
                return True
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if supplied and secrets.compare_digest(supplied, token):
                return True
            logger.warning(
                "API authentication rejected",
                extra={"event_name": "api.authentication_rejected", "outcome": "denied"},
            )
            self._send(401, {"error": "unauthorized"})
            return False

        def do_GET(self) -> None:
            with observed_request(self, "http_get"):
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
            with observed_request(self, "http_post"):
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
                    job = queue.enqueue(sample_path(root, payload.get("sample_path")), profile)
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                    self._send(400, {"error": str(exc)})
                    return
                logger.info(
                    "Analysis job enqueued",
                    extra={
                        "event_name": "job.enqueued",
                        "job_id": job["id"],
                        "profile": profile,
                        "outcome": "queued",
                    },
                )
                self._send(201, job)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return Handler


__all__ = ["MAX_REQUEST_BYTES", "PROFILES", "build_handler", "sample_path"]
