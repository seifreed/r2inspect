# REST API and worker

The API queues analysis jobs in SQLite and the worker executes them through the
same analysis pipeline as the CLI. Sample paths are relative to a fixed root.

```bash
r2inspect-api --database jobs.sqlite3 --sample-root ./samples
r2inspect-worker --database jobs.sqlite3 --sample-root ./samples
```

Create and inspect a job:

```bash
curl -X POST http://127.0.0.1:8080/v1/jobs \
  -H 'Content-Type: application/json' \
  -d '{"sample_path":"sample.exe","profile":"standard"}'
curl http://127.0.0.1:8080/v1/jobs/JOB_ID
```

`GET /health` reports process health. Set `R2INSPECT_API_TOKEN` or pass
`--token` and send `Authorization: Bearer TOKEN` when authentication is needed.
The server refuses non-localhost listeners without a token. Multiple workers
may share a database because each queued job is claimed in an atomic SQLite
transaction. `r2inspect-worker --once` processes at most one job.
