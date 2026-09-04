from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path

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
