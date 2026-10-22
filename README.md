# node-runtime-audit

```bash
curl -fsSLO https://raw.githubusercontent.com/The-DevOps-Daily/node-runtime-audit/main/node_runtime_audit.py
python3 node_runtime_audit.py      # as the user that owns the Node processes; root is not needed
```

Patching Node is a one-line version bump. Finding every Node your servers actually run is the work. This script lists the Node binary behind every running process and the places that will start Node later, and checks each one against the [Node.js security release of 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) (fixed in 22.23.4, 24.22.1 and 26.12.1; every end-of-life line counts as vulnerable).

It is one file of standard-library Python (3.8+, Linux). It never restarts, edits or upgrades anything, and it reads only five things: `/proc`, `pm2 jlist`, `crontab -l`, systemd unit files, and `node --version` inside running containers.

Run it as the user that owns the Node processes (the pm2 user, the app user). Running it as root is not needed. On a host where several users run Node, run it once as each of them.

Written for the DevOps Daily post: https://devops-daily.com/posts/node-october-2026-security-release-find-every-node

## What it checks

| Source | What it reports |
| --- | --- |
| `/proc` | Every running process whose binary (`readlink /proc/<pid>/exe`) is `node`, with the version compiled into that file, read through `/proc/<pid>/exe`. That works for deleted binaries and for processes inside containers. The parent chain shows `npm start` to `node`, `bun` to `next-server` and similar. |
| `pm2 jlist` | For your own `PM2_HOME`, when its daemon runs: the daemon's binary, each entry's interpreter and script when they point into one Node install, the first `node` on the entry's saved `PATH` (resolved against the app's cwd), the daemon's Node for cluster mode (the daemon forks the workers), and the Node processes running under each entry. |
| `crontab -l` | Absolute paths to `node`, `npm`, `npx` and anything inside a versioned Node install (`.../v24.14.0/...`), including `PATH=` lines. |
| systemd unit files | The same paths in units and drop-ins owned by root or by you, for example the unit `pm2 startup` writes. An `EnvironmentFile=` of a unit that runs Node is listed as not read. |
| `docker exec <id> node --version` | The Node on each running container's `PATH` (Docker and Podman). `--no-container-exec` uses the image's `NODE_VERSION` only, which stays unknown. |

Node binaries named in pm2 entries, crontabs and units are not opened. Their version comes from a running process that uses the same file; otherwise from the path as a hint: a path that names an unfixed version (`.../v24.14.0/bin/node`) counts as vulnerable, one that names a fixed version stays unknown. nvm, fnm, volta, asdf, mise, nodenv and n installs are listed the same way, for information.

Exit code: **1** if anything runs or will start a vulnerable Node, else **2** if anything it looked at could not be checked (a failed `pm2 jlist`, `crontab -l` or `docker ps`, an unreadable unit, a binary without an embedded version), else **0**. Unknown is never reported as patched. Distribution builds that link the system Brotli library (Debian's `nodejs`) are reported as unknown, because the fix for them comes from the distribution's packages, not from the version number.

```bash
python3 node_runtime_audit.py --json              # machine-readable
python3 node_runtime_audit.py --redact            # hide user names, home dirs and app names
python3 node_runtime_audit.py --fixed 22=22.23.4,24=24.22.1,26=26.12.1   # the default; change it for the next release
```

Run it on many hosts without copying it first, as the app user on each:

```bash
for h in deploy@web1 deploy@web2; do ssh "$h" 'python3 - --json' < node_runtime_audit.py > "node-${h#*@}.json"; done
```

## The other files

- `registry_scan.py`: which official `node` image tags ship a fixed Node, read from registry metadata only (manifest and config by digest, no layers). `scripts/summarize_registry.py` turns a scan into hours after the release.
- `lab/pm2-pin-lab.sh OLD_BIN NEW_BIN`: starts four pm2 apps (bare `node`, `npm start`, an absolute `--interpreter`, cluster mode) in a throwaway `PM2_HOME` on the old Node, switches `PATH` to the new one and records which binary each process really runs after `restart`, `restart --update-env`, delete and recreate, and `pm2 update`.
- `scripts/record-run.sh`: records a redacted run under `examples/`.
- `scripts/pgrep-vs-proc.sh`: compares `pgrep node` with the processes whose real binary is `node`.
- `scripts/pm2-path-evidence.py`: prints which Node install the saved pm2 list and the daemon's child processes have first on `PATH` (evidence for the post; not part of the audit).
- `tests/`: `python3 -m unittest discover -s tests -v`. Fake hosts with the cases a version check gets wrong: a deleted binary still running (also tested with a real process), a container binary, a distribution build, a pm2 entry whose config is fixed but whose process was never restarted, `npm` pinned to the old install while its child gets the new one, cluster mode, end-of-life and pre-release versions, a cron job on a removed version, an old binary in a directory named after a fixed version. And the safety cases: fake `node` scripts that leave a marker if anything runs them, a shell wrapper that mentions a fixed version, FIFOs, devices, hard links and symlinks where a file is expected, units owned by other users, escape codes in command lines and container names.

## Results

- `results/pm2-lab-20261022T063002Z.txt`: pm2 6.0.14 with Node v24.14.0 and v24.22.1.
- `examples/run-20261022T070555Z.txt`: the script on our Raspberry Pi.
- `results/pm2-path-20261022T070504Z.txt`: the pm2 app's `PATH` on the Pi, saved and running.
- `results/registry-20261022T062338Z.json`: 24 official tags, amd64 and arm64.
- `results/pgrep-vs-proc-20261022T063334Z.txt`: `pgrep -c node` returns 0 on the Pi while five processes run a `node` binary.

Facts and their sources are in [SOURCES.md](SOURCES.md).

## Safety

Everything the script finds can come from someone else: binaries, unit files, container names, process titles. So:

- **It never runs a binary it finds on the host.** The only version source for a running process is its binary, read through `/proc/<pid>/exe`: the `node-vX.Y.Z-headers.tar.gz` URL that official builds compile in, and only from an ELF file (a shell wrapper can mention any version). The read must be complete and the file unchanged while it is read. A version that only a directory name gives is a hint and never counts as patched.
- **Files are pinned before they are read.** `/proc/<pid>/exe` and unit files are opened with `O_PATH` (which never runs a device's open and never blocks on a FIFO), checked with `fstat` to be a regular file with exactly one link (a deleted binary has none), and only then reopened for reading through `/proc/self/fd/N` with `O_RDONLY | O_NONBLOCK`, so nothing can be swapped in between. Unit files owned by anyone other than root or you are skipped, and nothing a unit refers to (`EnvironmentFile=`, scripts) is read.
- **The commands it runs** are `pm2 jlist` (your own pm2, as you, only when a `PM2 v... God Daemon (<PM2_HOME>)` process of yours is running and the `pm2` CLI is owned by you or root and not writable by group or others), `crontab -l`, `systemctl show` for pm2 units, and `docker`/`podman` `ps`, `inspect` and `exec <id> node --version`. The last one runs the container's own binary inside the container, never on the host; `--no-container-exec` turns it off.
- **`--exec-version` is opt-in.** It runs `node --version` on binaries named in pm2 entries, crontabs and units only when root (or you, when you are not root) owns the file and every directory from `/` down to it, none of them is writable by group or others, and the file has one link; it executes the pinned file through `/proc/self/fd/N`. As root it refuses any binary not owned by root.
- **Output is sanitized.** Every control character (`0x00` to `0x1f`, `0x7f` and `0x80` to `0x9f`) from command lines, process names, file names and container names is printed as `\xNN`, in text and in JSON.
- **Secrets stay out.** It prints only the first two arguments of a command line and drops any that contain `=`. From pm2 environments, crontabs and units it prints only the Node paths, never whole lines or other variables.

## Limits

- Linux only (`/proc`). It sees the processes, crontab, pm2 and user units of the user running it; other users' processes are counted as not inspected.
- System crontabs (`/etc/crontab`, `/etc/cron.d`, `/etc/cron.daily`) and the saved pm2 list (`dump.pm2`) are not read. Check them with `grep` (the post has the command).
- A bare `node` in a cron job or unit is not resolved through that job's `PATH`; only absolute paths and `PATH=` lines are checked.
- A Node binary renamed to something other than `node` or `nodejs` (single executable applications, Electron) is not detected as a process.
- Kubernetes is not covered. Stopped containers and images that are not running are not covered. In a container, `node --version` reports the `node` on the container's `PATH`, not necessarily every Node in the image.

MIT licensed.
