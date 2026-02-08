#!/usr/bin/env bash
set -euo pipefail

coverage erase
coverage run --parallel-mode -m pytest -q tests/unit -k display_sections
coverage run --parallel-mode -m pytest -q tests/unit -k "not display_sections"
coverage combine
coverage report
