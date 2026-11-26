#!/usr/bin/env bash
#
# Checks for the Python bootstrap server.
#
# Requirements: pip install -r requirements.txt coverage ruff pip-audit
# The fixture tests need the lib repo at ./lib (CI checks it out there).
#
# Usage:
#   server.sh lint   Run Ruff without blocking the pipeline.
#   server.sh test   Run unit tests and write coverage files to build/ci.
#   server.sh audit  Check requirements.txt for known vulnerabilities.
#
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cmd_lint() {
    soft "ruff" ruff check . --output-format=github --exclude lib
}

cmd_test() {
    export HOPPIN_ENV=dev
    export HOPPIN_LIB_DIR="${HOPPIN_LIB_DIR:-$ROOT/lib}"

    # Run the test suite and keep its output for the metrics below. errexit is
    # off for this one pipeline so a failing run still writes its metrics.
    set +e
    coverage run --source=. --omit='tests/*,tools/*,lib/*' -m unittest discover -s tests -v 2>&1 | tee "$OUT_DIR/test.log"
    TEST_STATUS=${PIPESTATUS[0]}
    set -e

    # Generate human-readable and machine-readable coverage reports.
    coverage report --skip-empty | tee "$OUT_DIR/coverage.txt"
    coverage xml -o "$OUT_DIR/coverage.xml"

    # Extract the summary values used by CI artifacts.
    COVERAGE_PCT=$(tail -1 "$OUT_DIR/coverage.txt" | awk '{print $NF}' | sed 's/%//')
    # From unittest's own summary ("Ran N tests" and "OK"/"FAILED (...)"):
    # counting "ok" lines misses tests whose log output splits the line.
    SUMMARY=$(grep -E "^(OK|FAILED)" "$OUT_DIR/test.log" | tail -1 || true)
    count() { { echo "$SUMMARY" | grep -oE "$1=[0-9]+" || true; } | cut -d= -f2 | awk '{s+=$1} END {print s+0}'; }
    TEST_COUNT=$(sed -nE 's/^Ran ([0-9]+) tests?.*/\1/p' "$OUT_DIR/test.log" | tail -1)
    TEST_COUNT=${TEST_COUNT:-0}
    PASSED_COUNT=$(( TEST_COUNT - $(count failures) - $(count errors) - $(count skipped) - $(count "expected failures") ))

    # Write a compact summary for other pipeline steps and tools.
    cat > "$OUT_DIR/metrics.json" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "test_suite": "python_server",
  "total_tests": ${TEST_COUNT:-0},
  "passed_tests": ${PASSED_COUNT:-0},
  "coverage_percent": ${COVERAGE_PCT:-0},
  "exit_code": ${TEST_STATUS}
}
JSON

    return $TEST_STATUS
}

cmd_audit() {
    soft "pip-audit" pip-audit -r requirements.txt
}

dispatch "$@"
