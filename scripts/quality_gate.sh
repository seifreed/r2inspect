#!/usr/bin/env bash
# Quality gate for r2inspect.
#
# Runs every mandatory check declared in CLAUDE.md "Mandatory Quality Gates"
# and "No Inline Suppressions" sections, plus a clean-code marker scan.
#
# Every check must pass with zero errors and zero warnings. Any failure exits
# non-zero and the script reports a per-check summary at the end.
#
# Usage:
#   scripts/quality_gate.sh                 # run everything
#   scripts/quality_gate.sh --skip-audit    # skip pip-audit (no network)
#   scripts/quality_gate.sh --only ruff,mypy
#   scripts/quality_gate.sh -h
#
# Exit codes: 0 = all green, 1 = at least one check failed, 2 = bad usage.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

SRC_DIR="r2inspect"

# ---- pretty printing ---------------------------------------------------------

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    CYAN=$'\033[36m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; DIM=""; RESET=""
fi

print_header() {
    printf '\n%s==> %s%s\n' "$BOLD$CYAN" "$1" "$RESET"
}

print_pass() { printf '%s[PASS]%s %s\n' "$GREEN" "$RESET" "$1"; }
print_fail() { printf '%s[FAIL]%s %s\n' "$RED" "$RESET" "$1"; }
print_skip() { printf '%s[SKIP]%s %s\n' "$YELLOW" "$RESET" "$1"; }
print_info() { printf '%s%s%s\n' "$DIM" "$1" "$RESET"; }

# ---- argument parsing --------------------------------------------------------

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-2}"
}

SKIP_AUDIT=0
ONLY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --skip-audit) SKIP_AUDIT=1; shift ;;
        --only) ONLY="${2:-}"; shift 2 ;;
        --only=*) ONLY="${1#--only=}"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage 2 ;;
    esac
done

should_run() {
    local name="$1"
    if [[ -z "$ONLY" ]]; then
        return 0
    fi
    [[ ",${ONLY}," == *",${name},"* ]]
}

# ---- environment detection ---------------------------------------------------

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    for candidate in .venv venv; do
        if [[ -f "$REPO_ROOT/$candidate/bin/activate" ]]; then
            # shellcheck disable=SC1090
            source "$REPO_ROOT/$candidate/bin/activate"
            print_info "activated venv: $candidate"
            break
        fi
    done
fi

print_info "python: $(command -v python) ($(python --version 2>&1))"
print_info "repo:   $REPO_ROOT"

# ---- result tracking ---------------------------------------------------------

declare -a RESULTS=()

record() {
    # record <name> <status>
    RESULTS+=("$1|$2")
}

run_check() {
    # run_check <name> <human-label> <command...>
    local name="$1"; shift
    local label="$1"; shift
    if ! should_run "$name"; then
        print_skip "$label (filtered by --only)"
        record "$name" "skipped"
        return
    fi
    if ! command -v "$1" >/dev/null 2>&1; then
        print_fail "$label — required tool not found: $1"
        print_info "install dev extras:  pip install -e \".[dev]\""
        record "$name" "missing"
        return
    fi
    print_header "$label"
    print_info "$ $*"
    if "$@"; then
        print_pass "$label"
        record "$name" "pass"
    else
        print_fail "$label"
        record "$name" "fail"
    fi
}

# ---- check 1: black ----------------------------------------------------------

run_check "black" "black --check (formatter)" \
    black --check "$SRC_DIR"

# ---- check 2: ruff -----------------------------------------------------------

run_check "ruff" "ruff check (linter)" \
    ruff check "$SRC_DIR"

# ---- check 3: mypy -----------------------------------------------------------

# mypy returns non-zero on any error; warnings count as errors via
# warn_redundant_casts/warn_unused_ignores/warn_unreachable in pyproject.toml.
run_check "mypy" "mypy (type checker)" \
    mypy "$SRC_DIR"

# ---- check 4: bandit ---------------------------------------------------------

# `-c pyproject.toml` so it picks up [tool.bandit]; `--severity-level low`
# matches the configured floor and surfaces every finding.
run_check "bandit" "bandit (security linter)" \
    bandit -q -r "$SRC_DIR" -c pyproject.toml --severity-level low --confidence-level low

# ---- check 5: pip-audit ------------------------------------------------------

if [[ $SKIP_AUDIT -eq 1 ]]; then
    print_skip "pip-audit (skipped via --skip-audit)"
    record "pip-audit" "skipped"
elif ! should_run "pip-audit"; then
    print_skip "pip-audit (filtered by --only)"
    record "pip-audit" "skipped"
else
    # `--strict` makes warnings (e.g. skipped packages) fail the run.
    run_check "pip-audit" "pip-audit (dependency CVEs)" \
        pip-audit --strict --progress-spinner=off
fi

# ---- check 6: inline-suppression scan ----------------------------------------

scan_suppressions() {
    local pattern_label="$1"; shift
    local pattern="$1"; shift
    local hits
    # -n line numbers, -I skip binary, -E extended regex, --include only py files.
    if hits=$(grep -RnIE --include='*.py' "$pattern" "$SRC_DIR" 2>/dev/null); then
        printf '  %s%s%s found:\n' "$BOLD" "$pattern_label" "$RESET"
        printf '%s\n' "$hits" | sed 's/^/    /'
        return 1
    fi
    return 0
}

if should_run "suppressions"; then
    print_header "inline-suppression scan (CLAUDE.md policy)"
    found_any=0
    # The patterns mirror the forbidden list in CLAUDE.md > No Inline Suppressions.
    # Anchored with `#` so we only match real source comments, not strings.
    scan_suppressions "# nosec"           '#[[:space:]]*nosec([[:space:]]|$|:)'        || found_any=1
    scan_suppressions "# pragma: no cover" '#[[:space:]]*pragma:[[:space:]]*no[[:space:]]*cover' || found_any=1
    scan_suppressions "# noqa"            '#[[:space:]]*noqa([[:space:]]|$|:)'         || found_any=1
    scan_suppressions "# type: ignore"    '#[[:space:]]*type:[[:space:]]*ignore'       || found_any=1
    scan_suppressions "# pylint: disable" '#[[:space:]]*pylint:[[:space:]]*disable'    || found_any=1
    scan_suppressions "# fmt: off/on"     '#[[:space:]]*fmt:[[:space:]]*(off|on)'      || found_any=1
    scan_suppressions "# isort: skip/off" '#[[:space:]]*isort:[[:space:]]*(skip|off)'  || found_any=1

    if [[ $found_any -eq 0 ]]; then
        print_pass "inline-suppression scan"
        record "suppressions" "pass"
    else
        print_fail "inline-suppression scan — forbidden markers present"
        record "suppressions" "fail"
    fi
else
    print_skip "inline-suppression scan (filtered by --only)"
    record "suppressions" "skipped"
fi

# ---- check 7: mocks-and-monkeypatch scan ------------------------------------

scan_mocks() {
    # scan_mocks <label> <regex> <path...>
    local label="$1"; shift
    local pattern="$1"; shift
    local hits
    if hits=$(grep -RnIE --include='*.py' "$pattern" "$@" 2>/dev/null); then
        printf '  %s%s%s found:\n' "$BOLD" "$label" "$RESET"
        printf '%s\n' "$hits" | sed 's/^/    /'
        return 1
    fi
    return 0
}

if should_run "mocks"; then
    print_header "mocks / monkeypatch scan (CLAUDE.md policy)"
    if [[ ! -d tests ]]; then
        print_skip "tests/ not present"
        record "mocks" "skipped"
    else
        # Scope: both production source and tests are checked. Production code
        # should never import unittest.mock; tests must use FakeR2 + DI instead.
        SCAN_PATHS=("$SRC_DIR" tests)
        found_any=0

        # unittest.mock imports in any form
        scan_mocks "import unittest.mock"      '^[[:space:]]*(from[[:space:]]+unittest\.mock|from[[:space:]]+unittest[[:space:]]+import[[:space:]]+mock|import[[:space:]]+unittest\.mock)\b' \
            "${SCAN_PATHS[@]}" || found_any=1
        # pytest-mock
        scan_mocks "import pytest_mock / mocker fixture" \
            '^[[:space:]]*(import[[:space:]]+pytest_mock|from[[:space:]]+pytest_mock)\b|\bdef[[:space:]]+test_[A-Za-z0-9_]+\([^)]*\bmocker\b' \
            "${SCAN_PATHS[@]}" || found_any=1
        # Direct use of mock classes / patch decorators (covers `mock.patch`, `MagicMock()`, etc.)
        scan_mocks "Mock/MagicMock/AsyncMock/patch usage" \
            '\b(MagicMock|AsyncMock|PropertyMock|mock_open|create_autospec)\b|\bmock\.(patch|Mock|MagicMock|AsyncMock|PropertyMock|patch\.object|patch\.dict)\b|@patch\b|@patch\.object\b|@patch\.dict\b' \
            "${SCAN_PATHS[@]}" || found_any=1
        # monkeypatch fixture (param in test signature or attribute access)
        scan_mocks "pytest monkeypatch fixture" \
            '\bdef[[:space:]]+test_[A-Za-z0-9_]+\([^)]*\bmonkeypatch\b|\bmonkeypatch\.(setattr|setenv|delattr|delenv|setitem|delitem|syspath_prepend|chdir|context)\b' \
            "${SCAN_PATHS[@]}" || found_any=1
        # sys.modules import-injection
        scan_mocks "sys.modules injection" \
            '\bsys\.modules\[[^]]+\][[:space:]]*=' \
            "${SCAN_PATHS[@]}" || found_any=1

        if [[ $found_any -eq 0 ]]; then
            print_pass "mocks / monkeypatch scan"
            record "mocks" "pass"
        else
            print_fail "mocks / monkeypatch scan — forbidden constructs present"
            record "mocks" "fail"
        fi
    fi
else
    print_skip "mocks / monkeypatch scan (filtered by --only)"
    record "mocks" "skipped"
fi

# ---- summary -----------------------------------------------------------------

print_header "summary"
fail_count=0
miss_count=0
for entry in "${RESULTS[@]}"; do
    name="${entry%%|*}"
    status="${entry#*|}"
    case "$status" in
        pass)    printf '  %s%-14s PASS%s\n'    "$GREEN"  "$name" "$RESET" ;;
        fail)    printf '  %s%-14s FAIL%s\n'    "$RED"    "$name" "$RESET"; fail_count=$((fail_count+1)) ;;
        missing) printf '  %s%-14s MISSING%s\n' "$RED"    "$name" "$RESET"; miss_count=$((miss_count+1)) ;;
        skipped) printf '  %s%-14s SKIP%s\n'    "$YELLOW" "$name" "$RESET" ;;
    esac
done

echo
if [[ $fail_count -eq 0 && $miss_count -eq 0 ]]; then
    printf '%sall quality gates passed%s\n' "$GREEN$BOLD" "$RESET"
    exit 0
fi

if [[ $miss_count -gt 0 ]]; then
    printf '%s%d tool(s) missing — run: pip install -e ".[dev]"%s\n' "$RED" "$miss_count" "$RESET"
fi
if [[ $fail_count -gt 0 ]]; then
    printf '%s%d check(s) failed%s\n' "$RED$BOLD" "$fail_count" "$RESET"
fi
exit 1
