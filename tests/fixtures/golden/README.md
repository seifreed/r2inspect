# Golden Output Strategy

Golden outputs are stored as JSON fixtures in this directory and represent
expected results for real fixture binaries.

Guidelines:

- Store one file per fixture: `<fixture_name>.json`.
- Keep outputs stable by sorting keys and normalizing timestamps if needed.
- Update golden files only when behavior changes intentionally.
