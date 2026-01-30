#!/usr/bin/env bash
set -euo pipefail

# Minimal mutation testing target set for critical utils.
# Requires: pip install -e .[dev]

mutmut run --paths-to-mutate r2inspect/utils --tests-dir tests/unit
mutmut results
