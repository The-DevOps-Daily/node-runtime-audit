#!/usr/bin/env bash
# Record a redacted audit run as text and JSON under examples/.
# Usage: scripts/record-run.sh "<one-line description of the host>"
set -u
cd "$(dirname "$0")/.."
ts=$(date -u +%Y%m%dT%H%M%SZ)
txt="examples/run-$ts.txt"
{
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) ${1:-host}"
  echo "\$ python3 node_runtime_audit.py --redact"
  python3 -I node_runtime_audit.py --redact
  code=$?
  echo "\$ echo \$?"
  echo "$code"
} >"$txt" 2>&1
python3 -I node_runtime_audit.py --redact --json >"examples/run-$ts.json"
echo "$txt"
