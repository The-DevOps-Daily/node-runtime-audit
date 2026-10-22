#!/usr/bin/env bash
# Show which Node binary pm2 really runs before and after a Node upgrade.
#
# Apps: bare (`pm2 start server.js`), via-npm (`pm2 start npm -- start`),
# abs (`--interpreter /abs/old/node`) and clustered (`-i 1`, cluster mode).
#
# Usage: lab/pm2-pin-lab.sh OLD_NODE_BIN_DIR NEW_NODE_BIN_DIR [PM2_CLI]
#   e.g. lab/pm2-pin-lab.sh ~/.nvm/versions/node/v24.14.0/bin ~/.nvm/versions/node/v24.22.1/bin
#
# Everything runs in a throwaway PM2_HOME under $TMPDIR with a clean
# environment, so your real pm2 daemon and apps are not touched. The apps are
# a one-line script that only sleeps. The daemon is killed on exit.
set -euo pipefail

OLD=${1:?old Node bin dir}
NEW=${2:?new Node bin dir}
PM2=${3:-$(command -v pm2)}
PM2=$(readlink -f "$PM2")
HERE=$(cd "$(dirname "$0")" && pwd)
LAB=$(mktemp -d "${TMPDIR:-/tmp}/pm2-pin-lab.XXXXXX")
export PM2_HOME="$LAB/pm2home"
BASE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

pm2_in() { # pm2_in BIN_DIR args...: run pm2 from a shell where BIN_DIR is first in PATH
  local bin=$1
  shift
  (cd "$LAB/app" && env -i HOME="$LAB/home" PM2_HOME="$PM2_HOME" PATH="$bin:$BASE_PATH" \
    timeout 120 "$PM2" "$@") >>"$LAB/pm2.log" 2>&1
}

cleanup() {
  pm2_in "$NEW" kill || true
  pm2_in "$OLD" kill || true
  rm -rf "$LAB"
}
trap cleanup EXIT

mkdir -p "$LAB/home" "$LAB/app"
echo 'setInterval(() => {}, 1 << 30)' >"$LAB/app/server.js"
cat >"$LAB/app/package.json" <<'EOF'
{ "name": "lab-app", "private": true, "scripts": { "start": "node server.js" } }
EOF

CURRENT=$OLD
step() { echo "\$ pm2 $*" | sed -E 's#/home/[^/ ]+#/home/USER#g'; pm2_in "$CURRENT" "$@"; }
snap() {
  echo
  echo "== $1"
  sleep 5
  (cd "$LAB/app" && env -i HOME="$LAB/home" PM2_HOME="$PM2_HOME" PATH="$CURRENT:$BASE_PATH" \
    timeout 60 "$PM2" jlist 2>/dev/null) | python3 "$HERE/snapshot.py" "$PM2_HOME" "$LAB/app"
  echo
}
app_pids() {
  (cd "$LAB/app" && env -i HOME="$LAB/home" PM2_HOME="$PM2_HOME" PATH="$CURRENT:$BASE_PATH" \
    timeout 60 "$PM2" jlist 2>/dev/null) |
    python3 -c 'import json,sys; r=sys.stdin.read(); print(" ".join("%s=%s" % (a["name"], a.get("pid")) for a in json.loads(r[r.find("["):])))'
}

echo "# pm2-pin-lab $(date -u +%Y-%m-%dT%H:%M:%SZ) $(uname -m)"
# Read the pm2 version from its package.json: `pm2 --version` would start a daemon.
PM2_VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$(dirname "$PM2")/../package.json")
echo "# old: $("$OLD/node" --version)  new: $("$NEW/node" --version)  pm2: $PM2_VERSION"
echo "# app: a script that sleeps; package.json start script: node server.js"
echo

echo "## A. Before the upgrade: the old Node is first in PATH"
CURRENT=$OLD
step start server.js --name bare
step start npm --name via-npm -- start
step start server.js --name abs --interpreter "$OLD/node"
step start server.js --name clustered -i 1
snap "A. started from the old shell"

echo "## B. The upgrade: the new Node is now first in PATH (nvm/fnm default changed)"
CURRENT=$NEW
step restart bare
step restart via-npm
step restart abs
step restart clustered
snap "B1. pm2 restart from the new shell"

step restart bare --update-env
step restart via-npm --update-env
step restart abs --update-env
step restart clustered --update-env
snap "B2. pm2 restart --update-env from the new shell"

step delete via-npm
step delete abs
step start npm --name via-npm -- start
step start server.js --name abs --interpreter "$NEW/node"
snap "B3. via-npm and abs deleted and recreated from the new shell"

echo "## C. The daemon itself"
before=$(app_pids)
t0=$(date +%s.%N)
step update
t1=$(date +%s.%N)
after=$(app_pids)
echo "app pids before pm2 update: $before"
echo "app pids after pm2 update:  $after"
python3 -c "import sys; print('pm2 update took %.1f s' % (float(sys.argv[2]) - float(sys.argv[1])))" "$t0" "$t1"
snap "C. after pm2 update from the new shell"
