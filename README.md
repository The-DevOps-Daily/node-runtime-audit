# node-runtime-audit

```bash
curl -fsSLO https://raw.githubusercontent.com/The-DevOps-Daily/node-runtime-audit/main/node_runtime_audit.py
sudo python3 node_runtime_audit.py        # or without sudo: your own processes only
```

Patching Node is a one-line version bump. Finding every Node your servers actually run is the work. This script lists the Node binary behind every running process and every place that will start Node later, and checks each one against the [Node.js security release of 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) (fixed in 22.23.4, 24.22.1 and 26.12.1; every end-of-life line counts as vulnerable).

It is one file of standard-library Python (3.8+, Linux). It only reads: it never restarts, edits or upgrades anything.

Written for the DevOps Daily post: https://devops-daily.com/posts/node-october-2026-security-release-find-every-node

## What it checks

| Where | How |
| --- | --- |
| Running processes | `readlink /proc/<pid>/exe` for the real binary, then the version compiled into that file (read through `/proc/<pid>/exe`, so it works for deleted binaries and for processes inside containers). `--version` is also run when the file can only be changed by root or you, and the two must agree. |
| pm2, live | `pm2 jlist` for your own `PM2_HOME` when its daemon is running: the daemon's binary, each entry's interpreter and script when they point into one Node install, the first `node` on the entry's saved `PATH` (or the daemon's Node for cluster mode, which forks workers from the daemon), and the Node processes really running under the entry. |
| pm2, saved | `dump.pm2`, the list `pm2 resurrect` and a reboot start. |
| Version managers | nvm, fnm, volta, asdf, mise, nodenv and n installs, and the default alias. |
| Crontabs, systemd units | Absolute paths to `node`, `npm`, `npx` and anything inside a versioned Node install (`.../v24.14.0/...`), including `PATH=` lines and `pm2 startup` units. |
| Other files | `--scan-path DIR` searches scripts for the same paths. |
| Containers | `docker exec <id> node --version` (or podman) in each running container, plus `NODE_VERSION` from the image config. |

Exit code: **1** if anything runs or will start a vulnerable Node, else **2** if anything could not be checked, else **0**. Unknown is never reported as patched. Distribution builds that link the system Brotli library (Debian's `nodejs`) are reported as unknown, because the fix for them comes from the distribution's packages, not from the version number.

```bash
python3 node_runtime_audit.py --json              # machine-readable
python3 node_runtime_audit.py --redact            # hide user names, home dirs and pm2 app names
python3 node_runtime_audit.py --scan-path ~/bin   # also search your helper scripts
python3 node_runtime_audit.py --fixed 22=22.23.4,24=24.22.1,26=26.12.1   # the default; change it for the next release
```

Run it on many hosts without copying it first:

```bash
for h in web1 web2; do ssh "$h" 'sudo python3 - --json' < node_runtime_audit.py > "node-$h.json"; done
```

## The other files

- `registry_scan.py`: which official `node` image tags ship a fixed Node, read from registry metadata only (manifest and config by digest, no layers). `scripts/summarize_registry.py` turns a scan into hours after the release.
- `lab/pm2-pin-lab.sh OLD_BIN NEW_BIN`: starts four pm2 apps (bare `node`, `npm start`, an absolute `--interpreter`, cluster mode) in a throwaway `PM2_HOME` on the old Node, switches `PATH` to the new one and records which binary each process really runs after `restart`, `restart --update-env`, delete and recreate, and `pm2 update`.
- `scripts/record-run.sh`: records a redacted run under `examples/`.
- `scripts/pgrep-vs-proc.sh`: compares `pgrep node` with the processes whose real binary is `node`.
- `tests/`: `python3 -m unittest discover -s tests -v`. Fake hosts with the cases a version check gets wrong: a deleted binary still running, a container binary, a distribution build, a pm2 entry whose config is fixed but whose process was never restarted, `npm` pinned to the old install while its child gets the new one, end-of-life and pre-release versions, cron jobs on a removed version.

## Results

- `results/pm2-lab-20261022T063002Z.txt`: pm2 6.0.14 with Node v24.14.0 and v24.22.1.
- `examples/run-20261022T062905Z.txt`: the script on our Raspberry Pi.
- `results/registry-20261022T062338Z.json`: 24 official tags, amd64 and arm64.
- `results/pgrep-vs-proc-20261022T063334Z.txt`: `pgrep -c node` returns 0 on the Pi while five processes run a `node` binary.

Facts and their sources are in [SOURCES.md](SOURCES.md).

## Limits

- Linux only (`/proc`). Not root: other users' processes and crontabs are not visible, and the script says so.
- A Node binary renamed to something other than `node` or `nodejs` (single executable applications, Electron) is not detected as a process.
- `pm2 jlist` is only run for your own `PM2_HOME`, so other users' live pm2 environments are not read; their saved lists and processes are.
- Kubernetes is not covered. Stopped containers and images that are not running are not covered.

MIT licensed.
