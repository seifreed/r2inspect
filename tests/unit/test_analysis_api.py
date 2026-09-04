from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from r2inspect.application import api, worker
from r2inspect.application.api import create_server
from r2inspect.application.job_queue import JobQueue
from r2inspect.application.worker import process_next_job


def test_api_enqueues_and_worker_completes_job(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    database = tmp_path / "jobs.sqlite3"
    server = create_server(database, tmp_path, port=0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/v1/jobs",
            data=json.dumps({"sample_path": sample.name, "profile": "fast"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            job = json.load(response)
        assert response.status == 201
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

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
    server = create_server(tmp_path / "jobs.sqlite3", tmp_path, port=0, token="secret")
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def request(path: str, *, data: object | None = None, token: str | None = "secret"):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        body = None if data is None else json.dumps(data).encode()
        return urllib.request.urlopen(
            urllib.request.Request(base + path, data=body, headers=headers), timeout=2
        )

    try:
        with pytest.raises(urllib.error.HTTPError) as unauthorized:
            request("/health", token=None)
        assert unauthorized.value.code == 401
        with request("/health") as response:
            assert json.load(response) == {"status": "ok"}
        with pytest.raises(urllib.error.HTTPError) as missing:
            request("/v1/jobs/missing")
        assert missing.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as empty:
            urllib.request.urlopen(
                urllib.request.Request(
                    base + "/v1/jobs",
                    data=b"",
                    headers={"Authorization": "Bearer secret"},
                    method="POST",
                ),
                timeout=2,
            )
        assert empty.value.code == 400
        for path, data in (
            ("/wrong", {}),
            ("/v1/jobs", []),
            ("/v1/jobs", {"sample_path": sample.name, "profile": "invalid"}),
            ("/v1/jobs", {"sample_path": "../missing"}),
        ):
            with pytest.raises(urllib.error.HTTPError) as invalid:
                request(path, data=data)
            assert invalid.value.code in {400, 404}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


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
