#!/usr/bin/env bash
# Compare what `pgrep node` finds with the processes whose real binary is node.
# Process names lie (pm2 and Next.js rename themselves, and Node names its
# main thread "MainThread"); /proc/<pid>/exe does not. Output is redacted.
set -u
echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) $(uname -m)"
echo "\$ pgrep -c node"
pgrep -c node
echo "\$ pgrep -c -x node"
pgrep -c -x node
echo "# processes whose /proc/<pid>/exe is a node binary, with the name ps and pgrep see"
printf '%-8s %-16s %s\n' PID COMM EXE
for d in /proc/[0-9]*; do
  exe=$(readlink "$d/exe" 2>/dev/null) || continue
  case "${exe% (deleted)}" in */node | */nodejs) ;; *) continue ;; esac
  printf '%-8s %-16s %s\n' "${d#/proc/}" "$(cat "$d/comm")" "$exe"
done | sed -E 's#/home/[^/ ]+#/home/USER#g'
