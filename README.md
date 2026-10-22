# node-runtime-audit

```bash
curl -fsSLO https://raw.githubusercontent.com/The-DevOps-Daily/node-runtime-audit/main/node_runtime_audit.py
sudo python3 node_runtime_audit.py        # or without sudo: your own processes only
```

Patching Node is a one-line version bump. Finding every Node your servers actually run is the work. This script lists the Node binary behind every running process and every place that will start Node later, and checks each one against the [Node.js security release of 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) (fixed in 22.23.4, 24.22.1 and 26.12.1; every end-of-life line counts as vulnerable).

It is one file of standard-library Python (3.8+, Linux). It only reads: it never restarts, edits or upgrades anything, and by default it never runs a binary it finds (see Safety below).

Written for the DevOps Daily post: https://devops-daily.com/posts/node-october-2026-security-release-find-every-node

## What it checks

| Where | How |
| --- | --- |
| Running processes | `readlink /proc/<pid>/exe` for the real binary, then the version compiled into that file (read through `/proc/<pid>/exe`, so it works for deleted binaries and for processes inside containers), or `include/node/node_version.h` of the same install. A version from a directory name alone is shown as a hint and stays unknown. |
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
- `examples/run-20261022T063927Z.txt`: the script on our Raspberry Pi.
- `results/registry-20261022T062338Z.json`: 24 official tags, amd64 and arm64.
- `results/pgrep-vs-proc-20261022T063334Z.txt`: `pgrep -c node` returns 0 on the Pi while five processes run a `node` binary.

Facts and their sources are in [SOURCES.md](SOURCES.md).

## Safety

The script is meant to run as root on servers where other users run Node, so it treats everything it finds as untrusted:

- **It does not execute the binaries it finds.** The version comes from the file itself: the `node-vX.Y.Z-headers.tar.gz` URL that official builds compile in, read through `/proc/<pid>/exe`, or `include/node/node_version.h` of the install. Running `<path> --version` as root on a path that another user controls would run their code as root.
- **`--exec-version` is opt-in** and only runs a binary when root (or you, when you are not root) owns the file and every directory from `/` down to it, and none of them is writable by group or others. As root it refuses any binary not owned by root. The file is opened with `O_PATH | O_NOFOLLOW`, checked with `fstat` against the inode the process runs, and executed through `/proc/self/fd/N`, so it cannot be swapped between the check and the exec. If the result disagrees with the embedded version, the answer is unknown.
- **It does not block on planted files.** Every file it reads from a path someone else may control (crontabs, units, scripts, pm2 files, `node_version.h`, the binaries themselves) is opened non-blocking with `O_NOFOLLOW` after resolving symlinks, and must be a regular file by `lstat` and `fstat`, so a FIFO or device where a file should be is refused instead of stalling the run. Reads are capped. `node_version.h` is ignored unless it has the binary's owner and nobody else can write it.
- **Output is sanitized.** Command lines, process names, file names and container names and images come from other users and containers. Every control character (`0x00` to `0x1f`, `0x7f` and `0x80` to `0x9f`) is printed as `\xNN`, in text and in JSON, so nothing can send escape sequences to your terminal.
- **Secrets stay out.** It prints only the first two arguments of a command line and drops any that contain `=`. From pm2 environments, crontabs and units it prints only the Node paths, never whole lines or other variables.
- It only runs `pm2 jlist` for your own `PM2_HOME` and only when that daemon is already running, because `pm2 jlist` starts a daemon otherwise and, as root, would leave root-owned files in another user's `PM2_HOME`.

## Limits

- Linux only (`/proc`). Not root: other users' processes and crontabs are not visible, and the script says so.
- A Node binary renamed to something other than `node` or `nodejs` (single executable applications, Electron) is not detected as a process.
- `pm2 jlist` is only run for your own `PM2_HOME`, so other users' live pm2 environments are not read; their saved lists and processes are.
- Kubernetes is not covered. Stopped containers and images that are not running are not covered.

MIT licensed.
