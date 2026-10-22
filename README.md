# node-runtime-audit

```bash
curl -fsSLO https://raw.githubusercontent.com/The-DevOps-Daily/node-runtime-audit/main/node_runtime_audit.py
python3 node_runtime_audit.py      # as the user that owns the Node processes; root is not needed
```

Patching Node is a one-line version bump. Finding every Node your servers actually run is the work. This script lists the Node binary behind every running process and every place that will start Node later, and checks each one against the [Node.js security release of 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) (fixed in 22.23.4, 24.22.1 and 26.12.1; every end-of-life line counts as vulnerable).

It is one file of standard-library Python (3.8+, Linux). It only reads: it never restarts, edits or upgrades anything, and it never runs a binary it finds on the host (see Safety below).

Run it as the user that owns the Node processes (the pm2 user, the app user). Running it as root is not needed: it sees that user's processes, crontab, pm2 lists, version managers and units. On a host where several users run Node, run it once as each of them.

Written for the DevOps Daily post: https://devops-daily.com/posts/node-october-2026-security-release-find-every-node

## What it checks

| Where | How |
| --- | --- |
| Running processes | `readlink /proc/<pid>/exe` for the real binary, then the version compiled into that file, read through `/proc/<pid>/exe`, so it works for deleted binaries and for processes inside containers. A version that only a directory name gives is shown as a hint ("from path") and stays unknown. |
| pm2, live | `pm2 jlist` for your own `PM2_HOME` when its daemon is running: the daemon's binary, each entry's interpreter and script when they point into one Node install, the first `node` on the entry's saved `PATH` (resolved against the app's cwd), the daemon's Node for cluster mode (the daemon forks the workers), and the Node processes really running under the entry. |
| pm2, saved | `dump.pm2`, the list `pm2 resurrect` and a reboot start. fnm multishell directories on its `PATH` are skipped, because they do not survive a reboot. |
| Version managers | nvm, fnm, volta, asdf, mise, nodenv and n installs and the default alias, each judged by reading the binary. |
| Crontabs, systemd units | Absolute paths to `node`, `npm`, `npx` and anything inside a versioned Node install (`.../v24.14.0/...`), including `PATH=` lines, `EnvironmentFile=` files, `/etc/cron.daily` and similar scripts, and `pm2 startup` units. `npm` and `npx` start the first `node` on `PATH`, so a fixed Node next to them only counts as unknown. |
| Other files | `--scan-path DIR` searches scripts for the same paths. |
| Containers | `docker exec <id> node --version` (and podman) in each running container, plus `NODE_VERSION` from the image config. `--no-container-exec` uses the image metadata only, which is a hint and stays unknown. |

Exit code: **1** if anything runs or will start a vulnerable Node, else **2** if anything it looked at could not be checked (an unreadable config, a failed `pm2 jlist` or `docker ps`, a binary without an embedded version), else **0**. Unknown is never reported as patched. Distribution builds that link the system Brotli library (Debian's `nodejs`) are reported as unknown, because the fix for them comes from the distribution's packages, not from the version number.

```bash
python3 node_runtime_audit.py --json              # machine-readable
python3 node_runtime_audit.py --redact            # hide user names, home dirs and pm2 app names
python3 node_runtime_audit.py --scan-path ~/bin   # also search your helper scripts
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
- `tests/`: `python3 -m unittest discover -s tests -v`. Fake hosts with the cases a version check gets wrong: a deleted binary still running, a container binary, a distribution build, a pm2 entry whose config is fixed but whose process was never restarted, `npm` pinned to the old install while its child gets the new one, cluster mode, end-of-life and pre-release versions, cron jobs on a removed version, an old binary in a directory named after a fixed version. And the safety cases: fake `node` scripts that leave a marker if anything runs them, FIFOs, hard links and symlinks where a file is expected, escape codes in command lines and container names.

## Results

- `results/pm2-lab-20261022T063002Z.txt`: pm2 6.0.14 with Node v24.14.0 and v24.22.1.
- `examples/run-20261022T065509Z.txt`: the script on our Raspberry Pi.
- `results/registry-20261022T062338Z.json`: 24 official tags, amd64 and arm64.
- `results/pgrep-vs-proc-20261022T063334Z.txt`: `pgrep -c node` returns 0 on the Pi while five processes run a `node` binary.

Facts and their sources are in [SOURCES.md](SOURCES.md).

## Safety

Everything the script finds can come from someone else: other users' binaries and files, container names, process titles. So:

- **It never runs a binary it finds on the host.** The only version source is the binary itself: the `node-vX.Y.Z-headers.tar.gz` URL that official builds compile in. A version that only a directory name gives is a hint and never counts as patched. Anything else is unknown.
- **Files are pinned before they are read.** A binary or config file is opened with `O_PATH` (which never runs a device's open and never blocks on a FIFO), checked with `fstat` to be a regular file with exactly one link (a deleted binary seen through `/proc/<pid>/exe` has none), and only then reopened for reading through `/proc/self/fd/N` with `O_RDONLY | O_NONBLOCK`, so nothing can be swapped in between. A binary path from a config file is opened with `O_NOFOLLOW`: if its last component is a symlink, the result is unknown. Reads are capped, binaries are read in chunks rather than mapped, and a config file that is too large or unreadable makes the result unknown rather than clean.
- **`--exec-version` is opt-in.** It runs `node --version` only when root (or you, when you are not root) owns the file and every directory from `/` down to it, none of them is writable by group or others, the file has one link and is the inode that was read, and it executes it through `/proc/self/fd/N`. As root it refuses any binary not owned by root. If the result disagrees with the embedded version, the answer is unknown.
- **Containers.** By default it asks Docker or Podman to run `node --version` inside each running container. That runs the container's own binary inside the container, never on the host. `--no-container-exec` turns it off.
- **pm2.** It runs `pm2 jlist` only for your own `PM2_HOME`, only when the pid file points at a live `PM2 v...` daemon (`pm2 jlist` starts a daemon otherwise), and only when the `pm2` CLI is owned by you or root and not writable by group or others.
- **Output is sanitized.** Every control character (`0x00` to `0x1f`, `0x7f` and `0x80` to `0x9f`) from command lines, process names, file names and container names is printed as `\xNN`, in text and in JSON, so nothing can send escape sequences to your terminal.
- **Secrets stay out.** It prints only the first two arguments of a command line and drops any that contain `=`. From pm2 environments, crontabs and units it prints only the Node paths, never whole lines or other variables.

## Limits

- Linux only (`/proc`). It sees the processes, crontab and pm2 of the user running it; other users' processes are counted as not inspected. Run it as each user that owns Node processes.
- A bare `node` in a cron job or unit is not resolved through that job's `PATH`; only absolute paths and `PATH=` lines are checked.
- A Node binary renamed to something other than `node` or `nodejs` (single executable applications, Electron) is not detected as a process.
- Kubernetes is not covered. Stopped containers and images that are not running are not covered. In a container, `node --version` reports the `node` on the container's `PATH`, not necessarily every Node in the image.

MIT licensed.
