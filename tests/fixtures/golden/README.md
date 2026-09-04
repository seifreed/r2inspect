# Golden Output Strategy

Golden outputs are stored as JSON fixtures in this directory and represent
expected results for real fixture binaries.

Guidelines:

- Store one file per fixture: `<fixture_name>.json`.
- Keep outputs stable by sorting keys and normalizing timestamps if needed.
- Update golden files only when behavior changes intentionally.

The `export.*.json` fixtures are loaded by the official SARIF 2.1.0 JSON
Schema, STIX 2.1 library, and PyMISP in `test_report_exports.py`.
