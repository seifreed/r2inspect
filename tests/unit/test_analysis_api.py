from __future__ import annotations

import json
import logging
import socket
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from r2inspect.application import api, worker
from r2inspect.application.api import create_server
from r2inspect.application.job_queue import JobQueue
from r2inspect.application.worker import process_next_job
from r2inspect.infrastructure.logging import setup_logger


def _close_logger(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def _create_unbound_server(*args: Any, **kwargs: Any):
    real_server = api.ThreadingHTTPServer
    api.ThreadingHTTPServer = lambda address, handler: real_server(
        address, handler, bind_and_activate=False
    )
    try:
        return create_server(*args, **kwargs)
    finally:
        api.ThreadingHTTPServer = real_server


def _request(
    server: Any,
    path: str,
    *,
    method: str = "GET",
    data: object | None = None,
    token: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    body = b"" if data is None else json.dumps(data).encode()
    request_headers = {
        "Host": "localhost",
        "Connection": "close",
        **({"Authorization": f"Bearer {token}"} if token is not None else {}),
        **(headers or {}),
    }
    if method == "POST":
        request_headers["Content-Length"] = str(len(body))
        request_headers["Content-Type"] = "application/json"
    raw_headers = "".join(f"{key}: {value}\r\n" for key, value in request_headers.items())
    request = f"{method} {path} HTTP/1.1\r\n{raw_headers}\r\n".encode() + body
    client, handler_socket = socket.socketpair()
    client.sendall(request)
    client.shutdown(socket.SHUT_WR)
    thread = threading.Thread(
        target=server.RequestHandlerClass,
        args=(handler_socket, ("local", 0), server),
    )
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    handler_socket.close()
    chunks: list[bytes] = []
    while chunk := client.recv(64 * 1024):
        chunks.append(chunk)
    client.close()
    head, response_body = b"".join(chunks).split(b"\r\n\r\n", 1)
    lines = head.decode().split("\r\n")
    status = int(lines[0].split()[1])
    response_headers = dict(line.split(": ", 1) for line in lines[1:])
    return status, response_headers, json.loads(response_body)


def test_api_enqueues_and_worker_completes_job(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    database = tmp_path / "jobs.sqlite3"
    server = _create_unbound_server(database, tmp_path, port=0)
    try:
        status, _, job = _request(
            server,
            "/v1/jobs",
            method="POST",
            data={"sample_path": sample.name, "profile": "fast"},
        )
        assert status == 201
    finally:
        server.server_close()

    queue = JobQueue(database)
    assert process_next_job(
        queue,
        tmp_path,
        analyze=lambda path, profile: {"sample": path.name, "profile": profile},
    )
    completed = queue.get(job["id"])
    assert completed is not None
    assert completed["status"] == "completed"
    assert completed["result"] == {"sample": "sample.bin", "profile": "fast"}


def test_api_requires_token_outside_localhost(tmp_path: Path) -> None:
    try:
        create_server(tmp_path / "jobs.sqlite3", tmp_path, host="0.0.0.0", port=0)
    except ValueError as exc:
        assert "--token is required" in str(exc)
    else:
        raise AssertionError("external listener accepted without a token")
    with pytest.raises(ValueError, match="sample root is not a directory"):
        create_server(tmp_path / "jobs.sqlite3", tmp_path / "missing", port=0)


def test_api_authentication_and_request_validation(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    server = _create_unbound_server(tmp_path / "jobs.sqlite3", tmp_path, port=0, token="secret")

    try:
        assert _request(server, "/health")[0] == 401
        assert _request(server, "/health", token="secret")[2] == {"status": "ok"}
        assert _request(server, "/v1/jobs/missing", token="secret")[0] == 404
        assert _request(server, "/v1/jobs", method="POST", token="secret")[0] == 400
        for path, data in (
            ("/wrong", {}),
            ("/v1/jobs", []),
            ("/v1/jobs", {"sample_path": sample.name, "profile": "invalid"}),
            ("/v1/jobs", {"sample_path": "../missing"}),
        ):
            status, _, _ = _request(server, path, method="POST", data=data, token="secret")
            assert status in {400, 404}
    finally:
        server.server_close()


def test_worker_handles_empty_invalid_and_failed_jobs(tmp_path: Path) -> None:
    queue = JobQueue(tmp_path / "jobs.sqlite3")
    assert not process_next_job(queue, tmp_path)

    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"MZ")
    invalid = queue.enqueue(outside, "fast")
    assert process_next_job(queue, tmp_path)
    assert queue.get(invalid["id"])["status"] == "failed"

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    failed = queue.enqueue(sample, "fast")
    assert process_next_job(
        queue, tmp_path, analyze=lambda _path, _profile: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert queue.get(failed["id"])["error"] == "boom"


def test_api_and_worker_emit_correlated_structured_events(tmp_path: Path) -> None:
    log_path = tmp_path / "events.jsonl"
    root_logger = setup_logger(
        "r2inspect",
        level=logging.INFO,
        format_name="json",
        destination="file",
        log_file=log_path,
    )
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    database = tmp_path / "jobs.sqlite3"
    server = _create_unbound_server(database, tmp_path, port=0, token="server-secret")
    request_id = "request-123"
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    span_id = "00f067aa0ba902b7"
    try:
        status, response_headers, job = _request(
            server,
            "/v1/jobs",
            method="POST",
            data={"sample_path": sample.name, "profile": "fast"},
            token="server-secret",
            headers={
                "X-Request-ID": request_id,
                "X-Correlation-ID": "correlation-123",
                "traceparent": f"00-{trace_id}-{span_id}-01",
            },
        )
        assert status == 201
        assert response_headers["X-Request-ID"] == request_id

        queue = JobQueue(database)
        assert process_next_job(
            queue,
            tmp_path,
            analyze=lambda path, profile: {"sample": path.name, "profile": profile},
        )
    finally:
        server.server_close()
        for handler in root_logger.handlers:
            handler.flush()
        _close_logger(root_logger)

    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    by_name = {event["event_name"]: event for event in events}
    assert by_name["job.enqueued"]["request_id"] == request_id
    assert by_name["api.request_completed"]["correlation_id"] == "correlation-123"
    assert by_name["api.request_completed"]["trace_id"] == trace_id
    assert by_name["api.request_completed"]["span_id"] == span_id
    assert by_name["api.request_completed"]["duration_ms"] >= 0
    assert by_name["job.completed"]["correlation_id"] == job["id"]
    assert "server-secret" not in log_path.read_text(encoding="utf-8")


def test_api_unexpected_error_returns_500_and_logs_redacted_exception(tmp_path: Path) -> None:
    log_path = tmp_path / "errors.jsonl"
    root_logger = setup_logger(
        "r2inspect",
        level=logging.INFO,
        format_name="json",
        destination="file",
        log_file=log_path,
    )
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    server = _create_unbound_server(tmp_path / "jobs.sqlite3", tmp_path, port=0)
    original_enqueue = JobQueue.enqueue
    try:
        JobQueue.enqueue = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("token=exception-secret")
        )
        status, _, payload = _request(
            server,
            "/v1/jobs",
            method="POST",
            data={"sample_path": sample.name, "profile": "fast"},
        )
        assert status == 500
        assert payload == {"error": "internal server error"}
    finally:
        JobQueue.enqueue = original_enqueue  # type: ignore[method-assign]
        server.server_close()
        for handler in root_logger.handlers:
            handler.flush()
        _close_logger(root_logger)

    rendered = log_path.read_text(encoding="utf-8")
    event = next(
        json.loads(line)
        for line in rendered.splitlines()
        if json.loads(line).get("event_name") == "api.request_failed"
    )
    assert event["error_type"] == "RuntimeError"
    assert event["outcome"] == "error"
    assert "exception-secret" not in rendered


def test_worker_main_validates_poll_interval() -> None:
    original_argv = sys.argv
    try:
        sys.argv = [
            "r2inspect-worker",
            "--database",
            "jobs.db",
            "--sample-root",
            ".",
            "--poll-interval",
            "0",
        ]
        with pytest.raises(SystemExit, match="poll-interval must be positive"):
            worker.main()
    finally:
        sys.argv = original_argv


def test_api_and_worker_command_entry_points(tmp_path: Path) -> None:
    class Server:
        served = closed = False
        server_address = ("127.0.0.1", 8080)

        def serve_forever(self) -> None:
            self.served = True

        def server_close(self) -> None:
            self.closed = True

    server = Server()
    processed: list[tuple[Path, Path]] = []
    original_argv = sys.argv
    original_create_server = api.create_server
    original_process_next_job = worker.process_next_job
    original_sleep = worker.time.sleep
    try:
        api.create_server = lambda *_args, **_kwargs: server
        sys.argv = [
            "r2inspect-api",
            "--database",
            str(tmp_path / "jobs.db"),
            "--sample-root",
            str(tmp_path),
        ]
        api.main()
        assert server.served and server.closed

        worker.process_next_job = (
            lambda queue, root: processed.append((queue.database, root)) or False
        )
        sys.argv = [
            "r2inspect-worker",
            "--database",
            str(tmp_path / "jobs.db"),
            "--sample-root",
            str(tmp_path),
            "--once",
        ]
        worker.main()
        assert processed

        worker.time.sleep = lambda _delay: (_ for _ in ()).throw(KeyboardInterrupt())
        sys.argv = [
            "r2inspect-worker",
            "--database",
            str(tmp_path / "jobs.db"),
            "--sample-root",
            str(tmp_path),
        ]
        worker.main()

        api.create_server = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("invalid server")
        )
        with pytest.raises(SystemExit, match="invalid server"):
            api.main()
    finally:
        sys.argv = original_argv
        api.create_server = original_create_server
        worker.process_next_job = original_process_next_job
        worker.time.sleep = original_sleep
