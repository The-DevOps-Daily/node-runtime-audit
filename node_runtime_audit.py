#!/usr/bin/env python3
"""node-runtime-audit: find every Node.js a Linux host really runs and check
it against a Node.js security release.

It looks at:
  1. running processes: the real binary of each one (/proc/<pid>/exe), read
     even when it was deleted or lives in a container, and its version
  2. pm2: live entries (`pm2 jlist`) and the saved list (dump.pm2) that a
     reboot or `pm2 resurrect` brings back, with interpreter, script and PATH
     pinned to one Node install
  3. absolute Node paths in crontabs, systemd units and any extra paths
  4. `node --version` inside running Docker or Podman containers

It only reads. It never restarts, edits or upgrades anything. Exit code: 1 if
anything is vulnerable, else 2 if anything is unknown, else 0. Unknown is never
reported as patched.

Standard library only, Python 3.8+. MIT licensed.
"""

import argparse
import glob
import json
import mmap
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys

RELEASE = "Node.js security release of 2026-10-21"
FIXED_DEFAULT = "22=22.23.4,24=24.22.1,26=26.12.1"

NODE_EXE_RE = re.compile(r"^(node|nodejs)(\d+)?$")
NODE_TOOL_NAMES = {"node", "nodejs", "npm", "npx", "corepack"}
VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+]([0-9A-Za-z.\-]+))?$")
# process.release.headersUrl is compiled into official builds:
# https://nodejs.org/download/release/v24.22.1/node-v24.22.1-headers.tar.gz
EMBEDDED_RE = re.compile(rb"node-v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)-headers\.tar\.gz")
# A path component that names one install: nvm, fnm, n, volta, asdf, mise,
# nodenv (".../v24.14.0/..." or ".../24.14.0/...") or a tarball dir
# (".../node-v24.14.0-linux-x64/...").
PINNED_RE = re.compile(r"(?:^|/)(?:node-)?v?(\d+\.\d+\.\d+)(?:-[a-z0-9_-]+)?(?:/|$)")
ABS_PATH_RE = re.compile(r"/[A-Za-z0-9._@+%~/-]+")
FNM_MULTISHELL_RE = re.compile(r"/fnm_multishells/")

STATUS_ORDER = {"vulnerable": 3, "unknown": 2, "missing": 2, "patched": 1, "none": 0}
EXIT_FOR = {"vulnerable": 1, "unknown": 2, "missing": 2, "patched": 0, "none": 0}


# ---------------------------------------------------------------- versions

def parse_fixed(spec):
    fixed = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        line, _, ver = part.partition("=")
        m = VERSION_RE.match(ver.strip())
        if not line.strip().isdigit() or not m or m.group(4):
            raise ValueError("bad --fixed entry %r (want 24=24.22.1)" % part)
        fixed[int(line)] = tuple(int(x) for x in m.groups()[:3])
    if not fixed:
        raise ValueError("--fixed is empty")
    return fixed


def fmt(v):
    return "v%d.%d.%d" % v


def classify(version, fixed):
    """Return (status, reason) for a version string such as 'v24.14.0'."""
    if not version:
        return "unknown", "version not found"
    m = VERSION_RE.match(version.strip())
    if not m:
        return "unknown", "cannot parse version %r" % version
    if m.group(4):
        return "unknown", "pre-release or custom build %s" % version
    v = tuple(int(x) for x in m.groups()[:3])
    major = v[0]
    if major in fixed:
        if v >= fixed[major]:
            return "patched", "%s >= %s" % (fmt(v), fmt(fixed[major]))
        return "vulnerable", "%s < %s" % (fmt(v), fmt(fixed[major]))
    if major < max(fixed):
        return "vulnerable", "Node %d is end-of-life: no fixed release" % major
    return "unknown", "Node %d is newer than the fixed-release table" % major


def worst(statuses):
    best = "none"
    for s in statuses:
        if STATUS_ORDER.get(s, 2) > STATUS_ORDER[best]:
            best = s
    return best


def pinned_version(path):
    """The version named in a path component, or None."""
    m = PINNED_RE.search(path or "")
    return "v" + m.group(1) if m else None


# ---------------------------------------------------------------- binaries

class BinaryInspector:
    """Reads the version of a Node binary. The embedded headers URL is read
    from the file itself, so it works for deleted binaries (through
    /proc/<pid>/exe) and for binaries inside containers. `--version` is run
    only on files that only root or the current user can change, and both
    results must agree."""

    def __init__(self, allow_exec=True):
        self.allow_exec = allow_exec
        self.cache = {}

    def inspect(self, path, exec_path=None):
        try:
            st = os.stat(path)
        except OSError as e:
            return {"version": None, "method": None, "error": e.strerror, "shared": []}
        key = (st.st_dev, st.st_ino)
        if key not in self.cache:
            self.cache[key] = self._inspect(path, exec_path)
        return self.cache[key]

    def _inspect(self, path, exec_path):
        info = {"version": None, "method": None, "error": None, "shared": []}
        embedded = set()
        try:
            with open(path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if size:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        for m in EMBEDDED_RE.finditer(mm):
                            embedded.add("v" + m.group(1).decode())
                        for lib in (b"libnode.so", b"libbrotlidec.so"):
                            if mm.find(lib) != -1:
                                info["shared"].append(lib.decode())
        except (OSError, ValueError) as e:
            info["error"] = getattr(e, "strerror", None) or str(e)
        executed = None
        if exec_path and self.allow_exec and safe_to_exec(exec_path):
            executed = run_version([exec_path, "--version"])
        if len(embedded) > 1:
            info["error"] = "several versions embedded: %s" % ", ".join(sorted(embedded))
        elif embedded and executed and embedded != {executed}:
            info["error"] = "embedded %s but --version says %s" % (embedded.pop(), executed)
        elif embedded:
            info["version"] = embedded.pop()
            info["method"] = "embedded+--version" if executed else "embedded"
        elif executed:
            info["version"] = executed
            info["method"] = "--version"
        return info


def safe_to_exec(path):
    """Only execute binaries that nobody but root or us can replace."""
    try:
        st = os.stat(path)
        parent = os.stat(os.path.dirname(os.path.realpath(path)))
    except OSError:
        return False
    me = os.geteuid()
    owners = {0} if me == 0 else {0, me}
    for s in (st, parent):
        if s.st_uid not in owners or s.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
    return stat.S_ISREG(st.st_mode)


def run_version(argv, timeout=10):
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                             env={"PATH": "/usr/bin:/bin", "NODE_OPTIONS": ""})
    except (OSError, subprocess.SubprocessError):
        return None
    line = (out.stdout or "").strip().splitlines()
    if out.returncode == 0 and line and VERSION_RE.match(line[0].strip()):
        return line[0].strip()
    return None


def judge_binary(info, fixed):
    status, reason = classify(info.get("version"), fixed)
    if info.get("error") and not info.get("version"):
        reason = info["error"]
    if info.get("shared"):
        # Distribution builds link system libraries (Debian: libnode and
        # libbrotli) and backport fixes, so the upstream version decides nothing.
        status = "unknown"
        reason = ("distribution build linked to system %s (upstream says: %s); "
                  "check your distribution's nodejs and brotli advisories"
                  % (" and ".join(info["shared"]), reason))
    return status, reason


# ---------------------------------------------------------------- processes

def read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def proc_table(proc_root):
    """pid -> {ppid, comm, uid} for every process we can see."""
    table = {}
    for name in os.listdir(proc_root):
        if not name.isdigit():
            continue
        base = os.path.join(proc_root, name)
        try:
            raw = read(os.path.join(base, "stat"))
            close = raw.rfind(")")
            comm = raw[raw.find("(") + 1:close]
            ppid = int(raw[close + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        uid = None
        try:
            for line in read(os.path.join(base, "status")).splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
        except (OSError, ValueError):
            pass
        table[int(name)] = {"ppid": ppid, "comm": comm, "uid": uid}
    return table


def short_cmd(argv):
    """argv[0] and up to two arguments, never values that look like settings."""
    if not argv:
        return ""
    parts = [os.path.basename(argv[0])] if "/" in argv[0] and " " not in argv[0] else [argv[0]]
    for a in argv[1:3]:
        parts.append("<arg>" if ("=" in a or len(a) > 80) else a)
    s = " ".join(parts)
    return s if len(s) <= 90 else s[:87] + "..."


def username(uid):
    if uid is None:
        return "?"
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def scan_processes(proc_root, inspector, fixed, table):
    try:
        my_mnt = os.readlink(os.path.join(proc_root, "self", "ns", "mnt"))
    except OSError:
        my_mnt = None
    found, hidden = [], 0
    for pid in sorted(table):
        base = os.path.join(proc_root, str(pid))
        try:
            argv = [a.decode("utf-8", "replace")
                    for a in read(os.path.join(base, "cmdline"), "rb").split(b"\0") if a]
        except OSError:
            argv = []
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError as e:
            looks_node = argv and NODE_EXE_RE.match(os.path.basename(argv[0]))
            if looks_node and e.errno in (1, 13):
                found.append({"pid": pid, "status": "unknown", "reason":
                              "cannot read /proc/%d/exe (%s): run as root" % (pid, e.strerror),
                              "exe": None, "version": None, "cmd": short_cmd(argv),
                              "user": username(table[pid]["uid"]), "ppid": table[pid]["ppid"]})
            elif e.errno in (1, 13):
                hidden += 1
            continue
        deleted = exe.endswith(" (deleted)")
        path = exe[:-len(" (deleted)")] if deleted else exe
        if not NODE_EXE_RE.match(os.path.basename(path)):
            continue
        try:
            mnt = os.readlink(os.path.join(base, "ns", "mnt"))
        except OSError:
            mnt = None
        foreign = mnt is not None and my_mnt is not None and mnt != my_mnt
        # Read the binary through /proc/<pid>/exe, which is the inode the
        # process runs even if the file was replaced or lives in a container.
        # Run --version only on the same file in our own mount namespace.
        exec_path = None
        if not deleted and not foreign and same_file(path, os.path.join(base, "exe")):
            exec_path = path
        info = dict(inspector.inspect(os.path.join(base, "exe"), exec_path))
        deleted_libs, shared_libs = mapped_libs(base)
        info["shared"] = sorted(set(info.get("shared") or []) | set(shared_libs))
        status, reason = judge_binary(info, fixed)
        notes = []
        if deleted:
            notes.append("binary was replaced on disk: this process still runs the old file")
        if foreign:
            notes.append("other mount namespace (container): path is inside the container")
        if deleted_libs:
            notes.append("maps replaced libraries (restart needed): %s" % ", ".join(deleted_libs))
        found.append({"pid": pid, "ppid": table[pid]["ppid"], "user": username(table[pid]["uid"]),
                      "exe": path, "deleted": deleted, "container": foreign,
                      "version": info.get("version"), "method": info.get("method"),
                      "status": status, "reason": reason, "notes": notes,
                      "cmd": short_cmd(argv)})
    return found, hidden


def same_file(a, b):
    try:
        sa, sb = os.stat(a), os.stat(b)
    except OSError:
        return False
    return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)


def mapped_libs(base):
    """(replaced libraries still mapped, system libnode/libbrotlidec mapped)."""
    try:
        lines = read(os.path.join(base, "maps")).splitlines()
    except OSError:
        return [], []
    deleted, shared = set(), set()
    for line in lines:
        fields = line.split(None, 5)
        if len(fields) < 6:
            continue
        path = fields[5]
        name = os.path.basename(path.replace(" (deleted)", ""))
        if path.endswith("(deleted)") and re.match(r"lib(node|brotli|ssl|crypto|z|cares)", name):
            deleted.add(name)
        for lib in ("libnode.so", "libbrotlidec.so"):
            if name.startswith(lib):
                shared.add(lib)
    return sorted(deleted), sorted(shared)


def ancestry(pid, table, procs_by_pid, limit=4):
    chain = []
    cur = table.get(pid, {}).get("ppid")
    while cur and cur in table and len(chain) < limit:
        # Node names its main thread "MainThread", which says nothing here.
        name = "node" if cur in procs_by_pid else table[cur]["comm"]
        chain.append("%s(%d)" % (name, cur))
        cur = table[cur]["ppid"]
    return chain


def descendants(pid, table):
    kids = {}
    for p, row in table.items():
        kids.setdefault(row["ppid"], []).append(p)
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        for k in kids.get(p, []):
            out.append(k)
            todo.append(k)
    return set(out)


# ---------------------------------------------------------------- node paths

def node_for(path):
    """The node binary a path implies: itself, the node next to npm/npx, the
    node inside a bin directory, or the node of the versioned install that
    contains the path (a global package under lib/node_modules)."""
    base = os.path.basename(path)
    if base in ("node", "nodejs"):
        return path
    if base in NODE_TOOL_NAMES:
        return os.path.join(os.path.dirname(path), "node")
    if base == "bin":
        return os.path.join(path, "node")
    m = PINNED_RE.search(path)
    if m:
        root = path[:m.end()].rstrip("/")
        for rel in ("bin/node", "installation/bin/node"):
            cand = os.path.join(root, rel)
            if os.path.exists(cand):
                return cand
        return os.path.join(root, "bin", "node")
    return os.path.join(path, "node")


def judge_path(path, inspector, fixed):
    """Judge a Node path found in a config file. Pinned means the path itself
    names one install, so it will not follow the next upgrade."""
    node = node_for(path)
    pin = pinned_version(path)
    if os.path.exists(node):
        info = inspector.inspect(node, node)
        status, reason = judge_binary(info, fixed)
        version = info.get("version")
    else:
        version = pin
        status, reason = "missing", "%s does not exist" % node
        if pin:
            vstatus, vreason = classify(pin, fixed)
            reason += "; the path names %s (%s)" % (pin, vstatus)
    return {"path": path, "node": node, "pinned": bool(pin), "version": version,
            "status": status, "reason": reason}


def find_node_paths(text):
    """Yield (line_no, path) for absolute paths to Node binaries or to bin
    directories inside a versioned Node install. Comments are skipped."""
    for no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        seen = set()
        for m in ABS_PATH_RE.finditer(line):
            p = m.group(0).rstrip("/")
            if p.startswith("//") or line[max(0, m.start() - 1):m.start()] == ":" and \
                    line[max(0, m.start() - 6):m.start()].endswith(("http:", "https:")):
                continue  # a URL, not a path
            base = os.path.basename(p)
            # Node tools anywhere, and anything inside a versioned Node
            # install: its bin dir on a PATH line, or a global package such
            # as .../v24.14.0/lib/node_modules/pm2/bin/pm2.
            interesting = base in NODE_TOOL_NAMES or (
                pinned_version(p) and re.search(r"node", p, re.I))
            if interesting and p not in seen:
                seen.add(p)
                yield no, p


def scan_text_sources(sources, inspector, fixed):
    results = []
    for label, text in sources:
        for no, p in find_node_paths(text):
            r = judge_path(p, inspector, fixed)
            r["where"] = "%s:%d" % (label, no)
            results.append(r)
    return results


def crontab_sources(args):
    sources = []
    if args.crontab_file:
        for f in args.crontab_file:
            try:
                sources.append((f, read(f)))
            except OSError as e:
                sources.append((f, ""))
                print("note: cannot read %s: %s" % (f, e.strerror), file=sys.stderr)
        return sources
    if shutil.which("crontab"):
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                sources.append(("crontab -l (%s)" % username(os.geteuid()), out.stdout))
        except (OSError, subprocess.SubprocessError):
            pass
    pats = ["/etc/crontab", "/etc/cron.d/*"]
    if os.geteuid() == 0:
        pats += ["/var/spool/cron/crontabs/*", "/var/spool/cron/*"]
    for pat in pats:
        for f in sorted(glob.glob(pat)):
            if os.path.isfile(f):
                try:
                    sources.append((f, read(f)))
                except (OSError, UnicodeDecodeError):
                    pass
    return sources


SYSTEMD_DIRS = ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
                "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/systemd/user",
                "~/.config/systemd/user"]


def systemd_sources(dirs):
    sources = []
    for d in dirs:
        d = os.path.expanduser(d)
        for pat in ("*.service", "*.service.d/*.conf", "*.timer", "*/*.service"):
            for f in sorted(glob.glob(os.path.join(d, pat))):
                if not os.path.isfile(f):
                    continue
                try:
                    sources.append((f, read(f)))
                except (OSError, UnicodeDecodeError):
                    pass
    if os.geteuid() == 0:
        for f in sorted(glob.glob("/home/*/.config/systemd/user/*.service")):
            try:
                sources.append((f, read(f)))
            except (OSError, UnicodeDecodeError):
                pass
    # A unit can be listed twice through symlinks; keep the first.
    seen, out = set(), []
    for label, text in sources:
        real = os.path.realpath(label)
        if real not in seen:
            seen.add(real)
            out.append((label, text))
    return out


def extra_sources(paths):
    sources = []
    for root in paths:
        root = os.path.expanduser(root)
        files = [root] if os.path.isfile(root) else []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", ".cache")]
            if dirpath[len(root):].count(os.sep) >= 3:
                dirnames[:] = []
            files += [os.path.join(dirpath, f) for f in filenames]
        for f in sorted(files):
            try:
                if os.path.getsize(f) > 1 << 20:
                    continue
                data = read(f, "rb")
            except OSError:
                continue
            if b"\0" in data[:4096]:
                continue
            sources.append((f, data.decode("utf-8", "replace")))
    return sources


def pm2_unit_state(unit_path):
    """For a pm2 systemd unit, whether it is the thing running the daemon."""
    unit = os.path.basename(unit_path)
    if not shutil.which("systemctl"):
        return None
    try:
        out = subprocess.run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "MainPID"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    vals = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    return {"unit": unit, "active": vals.get("ActiveState"), "main_pid": vals.get("MainPID")}


# ---------------------------------------------------------------- installs

MANAGERS = [
    # (name, glob for each installed node binary, default alias file or link)
    ("nvm", "{nvm}/versions/node/*/bin/node", "{nvm}/alias/default"),
    ("fnm", "{fnm}/node-versions/*/installation/bin/node", "{fnm}/aliases/default"),
    ("volta", "{home}/.volta/tools/image/node/*/bin/node", None),
    ("asdf", "{home}/.asdf/installs/nodejs/*/bin/node", None),
    ("mise", "{home}/.local/share/mise/installs/node/*/bin/node", None),
    ("nodenv", "{home}/.nodenv/versions/*/bin/node", None),
    ("n", "/usr/local/n/versions/node/*/bin/node", None),
]


def installed_versions(homes, fixed):
    """Node installs kept by version managers. They only count when something
    uses them, so here only the default alias affects the exit code."""
    out, seen = [], set()
    for home in homes:
        nvm = os.environ.get("NVM_DIR") if home == os.path.expanduser("~") else None
        fnms = [os.environ.get("FNM_DIR")] if home == os.path.expanduser("~") else []
        fnms += [os.path.join(home, ".local/share/fnm"), os.path.join(home, ".fnm")]
        for name, pattern, alias in MANAGERS:
            for fnm in ([d for d in fnms if d] if name == "fnm" else [None]):
                ctx = {"home": home, "nvm": nvm or os.path.join(home, ".nvm"), "fnm": fnm}
                pat = pattern.format(**ctx)
                if pat in seen:
                    continue
                seen.add(pat)
                bins = sorted(glob.glob(pat))
                if not bins:
                    continue
                default = None
                if alias:
                    a = alias.format(**ctx)
                    if os.path.islink(a):
                        default = pinned_version(os.path.realpath(a))
                    elif os.path.isfile(a):
                        raw = read(a).strip()
                        default = raw if VERSION_RE.match(raw) else "alias %r" % raw
                versions = []
                for b in bins:
                    v = pinned_version(b)
                    st, why = classify(v, fixed)
                    versions.append({"version": v, "status": st})
                d_status = None
                if default:
                    d_status = classify(default, fixed)[0] if VERSION_RE.match(default) else "unknown"
                out.append({"manager": name, "where": os.path.dirname(pat.split("*")[0].rstrip("/")),
                            "versions": versions, "default": default, "default_status": d_status})
    which = shutil.which("node")
    shell = None
    if which:
        real = os.path.realpath(which)
        shell = {"path": which, "real": real, "version": pinned_version(real)}
        shell["status"] = classify(shell["version"], fixed)[0] if shell["version"] else "unknown"
    return out, shell


# ---------------------------------------------------------------- pm2

def resolve_on_path(path_value, name="node"):
    """First executable `name` on a saved PATH, like execvp would find it."""
    for d in (path_value or "").split(":"):
        if not d:
            continue
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return d, cand
    return None, None


def pm2_entry(entry, inspector, fixed, procs_by_pid, table, daemon=None):
    env = entry.get("pm2_env", entry)
    name = env.get("name") or entry.get("name") or "?"
    interp = env.get("exec_interpreter") or ""
    script = env.get("pm_exec_path") or ""
    path_value = env.get("PATH") or (env.get("env") or {}).get("PATH") or ""
    cluster = env.get("exec_mode") == "cluster_mode"
    findings = []

    if cluster:
        # Cluster workers are forked by the daemon with its own
        # process.execPath: interpreter and PATH do not choose the binary.
        if daemon and daemon.get("version"):
            findings.append({"what": "daemon node", "path": daemon.get("exe"), "pinned": False,
                             "version": daemon.get("version"), "status": daemon["status"],
                             "reason": "cluster mode runs on the daemon's Node: %s" % daemon.get("reason")})
        else:
            findings.append({"what": "daemon node", "path": None, "pinned": False, "version": None,
                             "status": "none", "reason": "cluster mode runs on whichever Node starts "
                             "the pm2 daemon (systemd unit PATH or your shell)"})
        interp = interp if interp.startswith("/") else ""
    if interp.startswith("/") and not cluster:
        r = judge_path(interp, inspector, fixed)
        r["what"] = "interpreter"
        findings.append(r)
    if script.startswith("/") and pinned_version(script) and re.search(r"node", script, re.I):
        r = judge_path(script, inspector, fixed)
        r["what"] = "script"
        findings.append(r)
    running = []
    pid = entry.get("pid") or env.get("pid")
    if pid:
        tree = {pid} | descendants(pid, table)
        running = [procs_by_pid[p] for p in sorted(tree) if p in procs_by_pid]
    # The saved PATH decides which node a bare `node` interpreter, a
    # `#!/usr/bin/env node` script or a child process gets. It does not
    # matter for an entry that runs Python or bash and starts no Node.
    other_interp = interp.startswith("/") and os.path.basename(interp) not in ("node", "nodejs") \
        or (interp and not interp.startswith("/") and interp not in ("node", "none"))
    d, node = resolve_on_path(path_value)
    if cluster or (other_interp and not running):
        pass
    elif d:
        r = judge_path(d, inspector, fixed)
        r["what"] = "PATH node"
        if FNM_MULTISHELL_RE.search(d):
            r["reason"] += "; fnm multishell dir: gone after reboot, then PATH falls through"
        findings.append(r)
    elif interp == "node":
        findings.append({"what": "PATH node", "path": None, "pinned": False, "version": None,
                         "status": "unknown", "reason": "no node on the saved PATH"})
    statuses = [f["status"] for f in findings] + [p["status"] for p in running]
    return {"name": name, "status_pm2": env.get("status"), "pid": pid, "cluster": cluster,
            "interpreter": env.get("exec_interpreter") or "",
            "script": script, "findings": findings, "running": running,
            "status": worst(statuses) if statuses else "none"}


def pm2_homes(args):
    if args.pm2_home:
        return [os.path.expanduser(h) for h in args.pm2_home]
    homes = [os.environ.get("PM2_HOME") or os.path.expanduser("~/.pm2")]
    if os.geteuid() == 0:
        homes += sorted(glob.glob("/home/*/.pm2")) + ["/root/.pm2"]
    out = []
    for h in homes:
        if os.path.isdir(h) and os.path.realpath(h) not in [os.path.realpath(x) for x in out]:
            out.append(h)
    return out


def load_json_list(raw):
    raw = raw or ""
    start = raw.find("[")
    if start == -1:
        return None
    try:
        data = json.loads(raw[start:])
    except ValueError:
        return None
    return data if isinstance(data, list) else None


def pm2_live(home, args, proc_root):
    """`pm2 jlist` for our own PM2_HOME, only if its daemon is already running
    (jlist would otherwise start one). Never for other users: the CLI would
    leave root-owned files in their PM2_HOME."""
    if args.pm2_jlist_file:
        return load_json_list(read(args.pm2_jlist_file)), None
    try:
        dpid = int(read(os.path.join(home, "pm2.pid")).strip())
    except (OSError, ValueError):
        return None, "no daemon pid file"
    if not os.path.exists(os.path.join(proc_root, str(dpid))):
        return None, "daemon not running"
    try:
        owner = os.stat(home).st_uid
    except OSError:
        return None, "cannot stat PM2_HOME"
    if owner != os.geteuid():
        return None, "owned by %s: live list skipped, saved list only" % username(owner)
    pm2 = args.pm2_bin or shutil.which("pm2")
    if not pm2:
        return None, "pm2 CLI not found"
    env = dict(os.environ, PM2_HOME=home)
    try:
        out = subprocess.run([pm2, "jlist"], capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "pm2 jlist failed: %s" % e
    data = load_json_list(out.stdout)
    return data, (None if data is not None else "pm2 jlist gave no JSON")


def pm2_daemon(home, proc_root, procs_by_pid):
    try:
        dpid = int(read(os.path.join(home, "pm2.pid")).strip())
    except (OSError, ValueError):
        return None
    return procs_by_pid.get(dpid) or ({"pid": dpid, "status": "unknown",
                                       "reason": "pid %d is not a visible Node process" % dpid}
                                      if os.path.exists(os.path.join(proc_root, str(dpid))) else None)


# ---------------------------------------------------------------- containers

def container_checks(cli, fixed):
    results = []
    try:
        out = subprocess.run([cli, "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "%s ps failed: %s" % (cli, e)
    if out.returncode != 0:
        return None, "%s ps failed: %s" % (cli, (out.stderr or "").strip().splitlines()[:1])
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        cid, name, image = parts[0], parts[1], parts[2]
        version = None
        try:
            r = subprocess.run([cli, "exec", "-e", "NODE_OPTIONS=", cid, "node", "--version"],
                               capture_output=True, text=True, timeout=30)
            first = (r.stdout or "").strip().splitlines()
            if r.returncode == 0 and first and VERSION_RE.match(first[0]):
                version = first[0].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        env_version = None
        try:
            r = subprocess.run([cli, "inspect", "--format",
                                "{{range .Config.Env}}{{println .}}{{end}}", cid],
                               capture_output=True, text=True, timeout=30)
            for env_line in r.stdout.splitlines():
                if env_line.startswith("NODE_VERSION="):
                    env_version = env_line.split("=", 1)[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        if not version and not env_version:
            continue
        if version:
            status, reason = classify(version, fixed)
            if env_version and env_version.lstrip("v") != version.lstrip("v"):
                reason += "; image ENV says NODE_VERSION=%s" % env_version
        else:
            status, reason = "unknown", ("no node on the container PATH; image ENV says "
                                         "NODE_VERSION=%s" % env_version)
        results.append({"id": cid[:12], "name": name, "image": image, "version": version,
                        "status": status, "reason": reason})
    return results, None


# ---------------------------------------------------------------- output

class Redactor:
    def __init__(self, on):
        self.on = on
        self.names = {}
        self.users = set()

    def user(self, u):
        if self.on and u and u not in ("root", "?"):
            self.users.add(u)
        return "USER" if (self.on and u and u not in ("root", "?")) else u

    def name(self, n):
        if not self.on:
            return n
        if n not in self.names:
            self.names[n] = "app-%d" % (len(self.names) + 1)
        return self.names[n]

    def __call__(self, s):
        if not self.on or s is None:
            return s
        s = str(s)
        s = re.sub(r"/home/[^/\s:]+", "/home/USER", s)
        s = re.sub(r"/run/user/\d+", "/run/user/UID", s)
        s = re.sub(r"\bpm2-[a-z_][a-z0-9_-]*\.service\b", "pm2-USER.service", s)
        for u in sorted(self.users, key=len, reverse=True):
            s = re.sub(r"(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_-])" % re.escape(u), "USER", s)
        for real, alias in sorted(self.names.items(), key=lambda kv: -len(kv[0])):
            s = re.sub(r"(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_])" % re.escape(real), alias, s)
        return s


def tag(status):
    return "[%s]" % status


def print_report(rep, red, out=None):
    w = (out or sys.stdout).write
    w("node-runtime-audit: %s, fixed releases %s\n" % (
        rep["release"], ", ".join(fmt(v) for _, v in sorted(rep["fixed"].items()))))
    w("lines without a fix (end-of-life) count as vulnerable\n")
    for n in rep.get("notes", []):
        w("note: %s\n" % red(n))

    w("\nRunning Node processes (real binary from /proc/<pid>/exe)\n")
    if not rep["processes"]:
        w("  none found\n")
    for p in rep["processes"]:
        w("  %-13s pid %-8s %-9s %-10s %s\n" % (
            tag(p["status"]), p["pid"], (p.get("version") or "?"), red.user(p.get("user")),
            red(p.get("exe") or "?")))
        w("      cmd: %s\n" % red(p.get("cmd")))
        if p.get("parents"):
            w("      parents: %s\n" % red(" <- ".join(p["parents"])))
        w("      why: %s\n" % red(p["reason"]))
        for n in p.get("notes", []):
            w("      note: %s\n" % red(n))
    if rep.get("hidden"):
        w("  %d other processes could not be inspected (run as root to see every user)\n"
          % rep["hidden"])

    for sec in rep["pm2"]:
        w("\npm2 %s (%s)\n" % (sec["kind"], red(sec["source"])))
        if sec.get("error"):
            w("  %s\n" % red(sec["error"]))
        d = sec.get("daemon")
        if d:
            w("  %-13s daemon pid %s %s %s\n" % (tag(d["status"]), d.get("pid"),
                                                d.get("version") or "?", red(d.get("exe") or "")))
        for e in sec.get("entries", []):
            w("  %-13s %s  %s%s%s\n" % (tag(e["status"]), red.name(e["name"]), e.get("status_pm2") or "",
                                        (" pid %s" % e["pid"]) if e.get("pid") else "",
                                        "  cluster mode" if e.get("cluster") else ""))
            w("      interpreter: %s\n" % red(e["interpreter"] or "-"))
            w("      script:      %s\n" % red(e["script"] or "-"))
            for f in e["findings"]:
                w("      %-12s %-9s %s%s\n" % (f["what"] + ":", f.get("version") or "?",
                                              red(f.get("path") or "-"),
                                              "  (pinned)" if f.get("pinned") else ""))
                if f["status"] != "patched" or f["what"] == "daemon node":
                    w("          %s: %s\n" % (f["status"], red(f["reason"])))
            if e["running"]:
                vers = sorted({p.get("version") or "?" for p in e["running"]})
                w("      running:     %d Node process(es) in this entry's tree: %s\n" % (
                    len(e["running"]), ", ".join(vers)))

    inst = rep.get("installs")
    if inst is not None:
        w("\nInstalled Node versions (version managers)\n")
        if not inst["managers"]:
            w("  none found\n")
        for m in inst["managers"]:
            w("  %s in %s\n" % (m["manager"], red(m["where"])))
            w("      installed: %s\n" % ", ".join("%s (%s)" % (v["version"], v["status"])
                                                for v in m["versions"]))
            if m["default"]:
                w("      %-13s default alias -> %s\n" % (tag(m["default_status"]), m["default"]))
        if inst.get("shell"):
            sh = inst["shell"]
            w("  %-13s `node` on this shell's PATH -> %s %s\n" % (
                tag(sh["status"]), sh.get("version") or "?", red(sh["real"])))
        w("  old installs are fine to keep for rollback; they matter when something above points at them\n")

    for key, title in (("cron", "Crontabs"), ("systemd", "systemd units"), ("extra", "Other files")):
        items = rep.get(key)
        if items is None:
            continue
        w("\n%s: absolute Node paths\n" % title)
        if not items:
            w("  none found\n")
        for r in items:
            w("  %-13s %s\n" % (tag(r["status"]), red(r["where"])))
            w("      %s -> %s%s\n" % (red(r["path"]), r.get("version") or "?",
                                     "  (pinned to one install)" if r.get("pinned") else ""))
            if r["status"] != "patched":
                w("      why: %s\n" % red(r["reason"]))
            if r.get("unit_state"):
                u = r["unit_state"]
                w("      unit: %s ActiveState=%s MainPID=%s\n" % (red(u["unit"]), u["active"], u["main_pid"]))
                if u["active"] != "active":
                    w("      note: the unit is not what runs pm2 now; its PATH applies at the next boot\n")

    w("\nContainers\n")
    if rep["containers"].get("error"):
        w("  %s\n" % red(rep["containers"]["error"]))
    for c in rep["containers"].get("items", []):
        w("  %-13s %s %s node %s\n" % (tag(c["status"]), red(c["name"]), c["image"], c.get("version") or "?"))
        if c["status"] != "patched":
            w("      why: %s\n" % c["reason"])

    w("\nresult: %s (exit %d)\n" % (rep["result"], rep["exit"]))


# ---------------------------------------------------------------- main

def build_report(args):
    fixed = parse_fixed(args.fixed)
    inspector = BinaryInspector(allow_exec=not args.no_exec)
    notes = []
    if os.geteuid() != 0:
        notes.append("not root: only your own processes, crontab and pm2 are fully visible")

    table = proc_table(args.proc_root)
    procs, hidden = scan_processes(args.proc_root, inspector, fixed, table)
    by_pid = {p["pid"]: p for p in procs}
    for p in procs:
        p["parents"] = ancestry(p["pid"], table, by_pid)

    pm2_sections = []
    if not args.no_pm2:
        homes = pm2_homes(args) if not args.pm2_jlist_file else [args.pm2_home[0] if args.pm2_home else "(file)"]
        for home in homes:
            live, err = pm2_live(home, args, args.proc_root)
            if live is not None or err:
                daemon = pm2_daemon(home, args.proc_root, by_pid)
                sec = {"kind": "live list", "source": "pm2 jlist, PM2_HOME=%s" % home,
                       "error": err if live is None else None, "daemon": daemon,
                       "entries": [pm2_entry(e, inspector, fixed, by_pid, table, daemon)
                                   for e in (live or [])]}
                pm2_sections.append(sec)
            dump = args.pm2_dump_file or os.path.join(home, "dump.pm2")
            if os.path.isfile(dump):
                try:
                    saved = load_json_list(read(dump))
                except OSError as e:
                    saved, notes_err = None, e.strerror
                sec = {"kind": "saved list", "source": "%s, what a reboot or pm2 resurrect starts" % dump,
                       "entries": [pm2_entry(e, inspector, fixed, {}, {}) for e in (saved or [])]}
                if saved is None:
                    sec["error"] = "cannot parse %s" % dump
                pm2_sections.append(sec)
            if args.pm2_dump_file:
                break

    rep = {"release": RELEASE, "fixed": fixed, "notes": notes, "processes": procs,
           "hidden": hidden, "pm2": pm2_sections, "containers": {}}
    if not args.no_installs:
        homes = [os.path.expanduser("~")]
        if os.geteuid() == 0:
            homes += sorted(glob.glob("/home/*"))
        managers, shell = installed_versions(homes, fixed)
        rep["installs"] = {"managers": managers, "shell": shell}
    if not args.no_cron:
        rep["cron"] = scan_text_sources(crontab_sources(args), inspector, fixed)
    if not args.no_systemd:
        sd = scan_text_sources(systemd_sources(args.systemd_dir or SYSTEMD_DIRS), inspector, fixed)
        for r in sd:
            unit_file = r["where"].rsplit(":", 1)[0]
            if "pm2" in os.path.basename(unit_file) and not args.systemd_dir:
                r["unit_state"] = pm2_unit_state(unit_file)
        rep["systemd"] = sd
    if args.scan_path:
        rep["extra"] = scan_text_sources(extra_sources(args.scan_path), inspector, fixed)

    if not args.no_containers:
        cli = args.container_cli or shutil.which("docker") or shutil.which("podman")
        if not cli:
            rep["containers"] = {"error": "no docker or podman CLI found", "items": []}
        else:
            items, err = container_checks(cli, fixed)
            rep["containers"] = {"error": err, "items": items or []}
    else:
        rep["containers"] = {"error": "skipped", "items": []}

    statuses = [p["status"] for p in procs]
    for sec in pm2_sections:
        statuses += [e["status"] for e in sec["entries"]]
        if sec.get("daemon"):
            statuses.append(sec["daemon"]["status"])
    for key in ("cron", "systemd", "extra"):
        statuses += [r["status"] for r in rep.get(key) or []]
    statuses += [c["status"] for c in rep["containers"].get("items", [])]
    for m in (rep.get("installs") or {}).get("managers", []):
        if m["default_status"]:
            statuses.append(m["default_status"])
    sh = (rep.get("installs") or {}).get("shell")
    if sh:
        statuses.append(sh["status"])
    overall = worst(statuses)
    rep["exit"] = EXIT_FOR.get(overall, 2)
    rep["result"] = {1: "VULNERABLE: something runs or will start an unfixed Node",
                     2: "UNKNOWN: something could not be checked; it is not patched until checked",
                     0: "nothing vulnerable found" if statuses else "no Node found"}[rep["exit"]]
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--fixed", default=FIXED_DEFAULT,
                    help="fixed release per line, default %s" % FIXED_DEFAULT)
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--redact", action="store_true",
                    help="hide user names, home dirs and pm2 app names (for sharing output)")
    ap.add_argument("--scan-path", action="append", default=[],
                    help="also search these files or dirs for absolute Node paths (repeatable)")
    ap.add_argument("--no-exec", action="store_true", help="never run --version, only read binaries")
    ap.add_argument("--no-pm2", action="store_true")
    ap.add_argument("--no-cron", action="store_true")
    ap.add_argument("--no-systemd", action="store_true")
    ap.add_argument("--no-containers", action="store_true")
    ap.add_argument("--no-installs", action="store_true", help="skip nvm/fnm/... install listing")
    ap.add_argument("--container-cli", help="docker or podman binary (default: auto)")
    ap.add_argument("--pm2-bin", help="pm2 CLI (default: pm2 on PATH)")
    ap.add_argument("--pm2-home", action="append", help="PM2_HOME to inspect (repeatable)")
    # For tests and offline review of files copied from a host:
    ap.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    ap.add_argument("--pm2-jlist-file", help=argparse.SUPPRESS)
    ap.add_argument("--pm2-dump-file", help=argparse.SUPPRESS)
    ap.add_argument("--crontab-file", action="append", help=argparse.SUPPRESS)
    ap.add_argument("--systemd-dir", action="append", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        rep = build_report(args)
    except ValueError as e:
        ap.error(str(e))
    red = Redactor(args.redact)
    for p in rep["processes"]:
        red.user(p.get("user"))
    red.user(username(os.geteuid()))
    if args.json:
        data = json.loads(json.dumps(rep, default=str))
        data["fixed"] = {str(k): fmt(v) for k, v in rep["fixed"].items()}
        if args.redact:
            for sec in data["pm2"]:
                for e in sec["entries"]:
                    e["name"] = red.name(e["name"])
            data = json.loads(red(json.dumps(data)))
        print(json.dumps(data, indent=2))
    else:
        if args.redact:
            for sec in rep["pm2"]:
                for e in sec["entries"]:
                    red.name(e["name"])
        print_report(rep, red)
    return rep["exit"]


if __name__ == "__main__":
    sys.exit(main())
