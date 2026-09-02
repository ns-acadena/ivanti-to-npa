#!/usr/bin/env bash
# Runs every _smoketest_*.py file (ad-hoc dev tests, not shipped) plus a
# module-import sanity check. This is the canonical regression command --
# use this instead of typing out the file list by hand, so a test file
# never silently drops off the list again (that happened once to
# _smoketest_verify.py before this script existed).
set -uo pipefail
cd "$(dirname "$0")"

python3 -c "import main, mapper, ivanti_parser, netskope_client, validation, runlog, publisher_ui, policy_group_ui, report" \
  && echo "IMPORTS OK" || { echo "IMPORT FAILURE"; exit 1; }

fail_count=0
for f in _smoketest_*.py; do
  out=$(python3 "$f" 2>&1)
  if [ $? -eq 0 ]; then
    echo "PASS $f"
  else
    echo "FAIL $f"
    echo "$out" | tail -20
    fail_count=$((fail_count + 1))
  fi
done

echo
if [ "$fail_count" -eq 0 ]; then
  echo "ALL TESTS PASSED"
else
  echo "$fail_count TEST FILE(S) FAILED"
  exit 1
fi
