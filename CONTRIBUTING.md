# Contributing

## Setup

Requirements are Python 3.13 or newer, radare2 6.1.8, and the native libraries
required by the selected optional analyzers.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Checks

Run the required quality gate and focused tests before opening a pull request:

```bash
bash scripts/quality_gate.sh
python -m pytest -q tests/unit
python -m pytest -q tests/integration
```

Changes to detection logic must include a labeled positive case, a benign
negative case, and explicit behavior for extraction errors. Tests that require
POSIX-only APIs must use `@pytest.mark.requires_posix`; tests that require a
real radare2 process must use `@pytest.mark.requires_r2`.

Keep pull requests focused. Document output contract changes in
`docs/output-schema.md` and user-visible changes in `CHANGELOG.md`.
