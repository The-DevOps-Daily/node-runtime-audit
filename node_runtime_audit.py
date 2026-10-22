#!/usr/bin/env python3
"""node-runtime-audit: find every Node.js a Linux host really runs and check
it against a Node.js security release.

It reads only these:
  1. /proc: the real binary of each running process (/proc/<pid>/exe), read
     even when it was deleted or lives in a container, and its version
  2. `pm2 jlist`: live entries with interpreter, script and PATH pinned to
     one Node install, and the Node processes running under each entry
  3. `crontab -l` and systemd unit files: absolute Node paths
  4. `docker exec <id> node --version` (and podman) in running containers
Node binaries found in pm2 entries, crontabs and units are not read: their
version comes from a running process that uses the same file, or from the
path as a hint (an unfixed version in the path counts as vulnerable, a fixed
one stays unknown).

It only reads. It never restarts, edits or upgrades anything, and it does not
run the binaries it finds unless you pass --exec-version. Exit code: 1 if
anything is vulnerable, else 2 if anything is unknown, else 0. Unknown is never
reported as patched.

Standard library only, Python 3.8+. MIT licensed.
"""

import argparse
import errno
import glob
import json
import os
import pwd
import re
import shlex
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

# C0 controls, DEL and C1 controls. Process names, command lines, file names
# and container names come from other users and containers; printed raw they
# could move the cursor, rewrite the screen or set the terminal title.
CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f]")

STATUS_ORDER = {"vulnerable": 3, "unknown": 2, "missing": 2, "patched": 1, "none": 0}
EXIT_FOR = {"vulnerable": 1, "unknown": 2, "missing": 2, "patched": 0, "none": 0}


# ---------------------------------------------------------------- output safety

def clean(text):
    """Escape control characters as \\xNN so nothing can reach the terminal raw."""
    return CONTROL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)), text)


def clean_tree(obj):
    """clean() every string in a report, keys included."""
    if isinstance(obj, str):
        return clean(obj)
    if isinstance(obj, dict):
        return {clean_tree(k): clean_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean_tree(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(clean_tree(x) for x in obj)
    return obj


# ---------------------------------------------------------------- safe reads

MAX_READ = 4 << 20       # config files, unit files, scripts
MAX_BINARY = 512 << 20   # Node binaries are about 100 to 130 MB


def open_pinned(path, follow=True, allow_unlinked=False):
    """Open a file someone else may control, for reading, without blocking.

    The path is first opened with O_PATH, which never runs a device's open
    and never blocks on a FIFO. fstat on that handle must show a regular file
    with exactly one link (or none, for a deleted binary seen through
    /proc/<pid>/exe, when allow_unlinked). Only then is the same inode
    reopened for reading through /proc/self/fd/N with O_RDONLY, O_NONBLOCK
    and O_CLOEXEC, so nothing can be swapped in between. follow=False adds
    O_NOFOLLOW: a symlink as the last path component is refused.
    Returns (fd, stat)."""
    pfd = os.open(path, os.O_PATH | os.O_CLOEXEC | (0 if follow else os.O_NOFOLLOW))
    try:
        st = os.fstat(pfd)
        if stat.S_ISLNK(st.st_mode):
            raise OSError(errno.ELOOP, "is a symlink", path)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        if st.st_nlink != 1 and not (allow_unlinked and st.st_nlink == 0):
            raise OSError(errno.EMLINK, "has %d hard links" % st.st_nlink, path)
        fd = os.open("/proc/self/fd/%d" % pfd, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    finally:
        os.close(pfd)
    st2 = os.fstat(fd)
    if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        raise OSError(errno.EAGAIN, "file changed while opening", path)
    return fd, st2


def safe_read(path, limit=MAX_READ, binary=False):
    """Read at most `limit` bytes of a regular, singly linked file."""
    fd, _ = open_pinned(path)
    try:
        chunks, size = [], 0
        while size < limit:
            chunk = os.read(fd, min(65536, limit - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    return data if binary else data.decode("utf-8", "replace")


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
        v = tuple(int(x) for x in m.groups()[:3])
        if int(line) != v[0]:
            raise ValueError("bad --fixed entry %r: the version is not on line %s" % (part, line))
        fixed[int(line)] = v
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
    """Reads the version of a Node binary without running it.

    The only source is the binary itself: official builds compile in their
    headers URL (node-vX.Y.Z-headers.tar.gz). For a process the file is opened
    through /proc/<pid>/exe, the inode the process runs, even when it was
    deleted or lives in a container. A version that only a directory name
    gives ("from path") is a hint and never counts as patched. --exec-version
    adds a `--version` cross-check through exec_version_hardened().
    """

    def __init__(self, exec_version=False):
        self.exec_version = exec_version
        self.cache = {}

    def inspect(self, path, exec_path=None, magic=False):
        """path: the file to read. magic=True for /proc/<pid>/exe, which has to
        be followed; any other path is opened with O_NOFOLLOW. exec_path: the
        file to run with --exec-version."""
        try:
            fd, st = open_pinned(path, follow=magic, allow_unlinked=magic)
        except OSError as e:
            return {"version": None, "method": None, "shared": [],
                    "error": "cannot read the binary: %s" % (e.strerror or e)}
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, bool(exec_path and self.exec_version))
        try:
            if key not in self.cache:
                self.cache[key] = self._inspect(fd, st, exec_path)
                self.cache[key]["inode"] = [st.st_dev, st.st_ino]
        finally:
            os.close(fd)
        return self.cache[key]

    def _inspect(self, fd, st, exec_path):
        info = {"version": None, "method": None, "error": None, "shared": []}
        embedded = set()
        if st.st_size > MAX_BINARY:
            info["error"] = "file larger than %d MB, not read" % (MAX_BINARY >> 20)
            return info
        try:
            # pread in chunks with an overlap, not mmap: a file truncated
            # while we read it ends the loop instead of raising SIGBUS.
            pos, tail, shared = 0, b"", set()
            while pos < st.st_size:
                chunk = os.pread(fd, min(1 << 20, st.st_size - pos), pos)
                if not chunk:
                    break
                buf = tail + chunk
                for m in EMBEDDED_RE.finditer(buf):
                    embedded.add("v" + m.group(1).decode())
                for lib in (b"libnode.so", b"libbrotlidec.so"):
                    if lib in buf:
                        shared.add(lib.decode())
                tail = buf[-256:]
                pos += len(chunk)
            info["shared"] = sorted(shared)
            head = os.pread(fd, 4, 0)
            after = os.fstat(fd)
        except (OSError, ValueError) as e:
            info["error"] = getattr(e, "strerror", None) or str(e)
            return info
        if pos < st.st_size or (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
            info["error"] = "the file changed or ended early while it was read"
            return info
        if head != b"\x7fELF":
            # A shell wrapper can mention any version and start another Node.
            info["error"] = "not an ELF binary: an embedded version is only taken from one"
            return info
        if len(embedded) > 1:
            info["error"] = "several versions embedded: %s" % ", ".join(sorted(embedded))
            return info
        found = embedded.pop() if embedded else None
        executed = None
        if exec_path and self.exec_version:
            executed, why = exec_version_hardened(exec_path, (st.st_dev, st.st_ino))
            if executed is None:
                info["exec_refused"] = why
        if found and executed and found != executed:
            info["error"] = "embedded %s but --version says %s" % (found, executed)
            return info
        if found:
            info["version"], info["method"] = found, "embedded" + ("+--version" if executed else "")
            if info.get("exec_refused"):
                info["note"] = "--exec-version refused: %s" % info["exec_refused"]
        elif executed:
            info["version"], info["method"] = executed, "--version"
        return info


def trusted_owner_ok(st, me):
    """Root, or us when we are not root; never writable by group or others."""
    return not untrusted_reason(st, me)


def untrusted_reason(st, me):
    """Why a file or directory could have been changed by someone else, or ''."""
    owners = {0} if me == 0 else {0, me}
    if st.st_uid not in owners:
        return "owned by uid %d" % st.st_uid
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "writable by group or others (mode %o)" % stat.S_IMODE(st.st_mode)
    return ""


def exec_version_hardened(path, expect=None, timeout=10):
    """Run `<node> --version` only when nobody but root (or us, when not root)
    can have changed the file or any directory above it. The file is pinned
    with an O_PATH descriptor, must be the inode that was read, and is
    executed through /proc/self/fd/N, so it cannot be swapped between the
    checks and the exec. Returns (version, why)."""
    me = os.geteuid()
    try:
        real = os.path.realpath(path)
        fd = os.open(real, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, AttributeError) as e:
        return None, "cannot open: %s" % (getattr(e, "strerror", None) or e)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return None, "not a regular file with one link"
        if expect and (st.st_dev, st.st_ino) != tuple(expect):
            return None, "file changed since it was found"
        if me == 0 and st.st_uid != 0:
            return None, "running as root: refusing a binary not owned by root"
        if not trusted_owner_ok(st, me):
            return None, "binary %s" % untrusted_reason(st, me)
        d = os.path.dirname(real)
        while True:
            try:
                dst = os.stat(d)
            except OSError as e:
                return None, "cannot stat %s: %s" % (d, e.strerror)
            if not trusted_owner_ok(dst, me):
                return None, "directory %s is %s" % (d, untrusted_reason(dst, me))
            if d == "/":
                break
            d = os.path.dirname(d)
        try:
            out = subprocess.run(["/proc/self/fd/%d" % fd, "--version"], pass_fds=(fd,),
                                 capture_output=True, text=True, timeout=timeout,
                                 env={"PATH": "/usr/bin:/bin"}, cwd="/")
        except (OSError, subprocess.SubprocessError) as e:
            return None, "exec failed: %s" % e
        line = (out.stdout or "").strip().splitlines()
        if out.returncode == 0 and line and VERSION_RE.match(line[0].strip()):
            return line[0].strip(), None
        return None, "--version gave no version"
    finally:
        os.close(fd)


def judge_binary(info, fixed, name_hint=None):
    status, reason = classify(info.get("version"), fixed)
    if info.get("error") and not info.get("version"):
        reason = info["error"]
    if not info.get("version") and name_hint:
        reason += "; from path: %s (a hint, not proof)" % name_hint
    if info.get("exec_refused"):
        reason += "; --exec-version refused: %s" % info["exec_refused"]
    if info.get("shared"):
        # Distribution builds link system libraries (Debian: libnode and
        # libbrotli) and backport fixes, so the upstream version decides nothing.
        status = "unknown"
        reason = ("distribution build linked to system %s (upstream says: %s); "
                  "check your distribution's nodejs and brotli advisories"
                  % (" and ".join(info["shared"]), reason))
    return status, reason


# ---------------------------------------------------------------- processes

def read_proc(path, mode="r"):
    """Read a procfs file (kernel-generated; never user-controlled)."""
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
            raw = read_proc(os.path.join(base, "stat"))
            close = raw.rfind(")")
            comm = raw[raw.find("(") + 1:close]
            ppid = int(raw[close + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        uid = None
        try:
            for line in read_proc(os.path.join(base, "status")).splitlines():
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
                    for a in read_proc(os.path.join(base, "cmdline"), "rb").split(b"\0") if a]
        except OSError:
            argv = []
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError as e:
            looks_node = argv and NODE_EXE_RE.match(os.path.basename(argv[0]))
            if looks_node and e.errno in (1, 13):
                found.append({"pid": pid, "status": "unknown", "reason":
                              "cannot read /proc/%d/exe (%s): run the script as its owner" % (pid, e.strerror),
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
        # Read the binary through /proc/<pid>/exe: the inode the process
        # runs. --exec-version only applies to the same file in our own mount
        # namespace, never to a replaced (deleted) binary.
        own = not deleted and not foreign and same_file(path, os.path.join(base, "exe"))
        info = dict(inspector.inspect(os.path.join(base, "exe"),
                                      exec_path=path if own else None, magic=True))
        deleted_libs, shared_libs = mapped_libs(base)
        info["shared"] = sorted(set(info.get("shared") or []) | set(shared_libs))
        status, reason = judge_binary(info, fixed, pinned_version(path))
        notes = []
        if deleted:
            notes.append("binary was replaced on disk: this process still runs the old file")
        if foreign:
            notes.append("other mount namespace (container): path is inside the container")
        if deleted_libs:
            notes.append("maps replaced libraries (restart needed): %s" % ", ".join(deleted_libs))
        found.append({"pid": pid, "ppid": table[pid]["ppid"], "user": username(table[pid]["uid"]),
                      "exe": path, "deleted": deleted, "container": foreign, "inode": info.get("inode"),
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
        lines = read_proc(os.path.join(base, "maps")).splitlines()
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


def hint_status(hint, fixed, why="binaries outside /proc are not read"):
    """Judge a version taken from a path name. A path that names an unfixed
    version counts as vulnerable; one that names a fixed version stays
    unknown, because the binary in it was not checked."""
    if not hint:
        return "unknown", "version not known: %s" % why
    status, reason = classify(hint, fixed)
    if status == "vulnerable":
        return "vulnerable", "from path: %s, %s (%s)" % (hint, reason, why)
    return "unknown", "from path: %s (a hint, not proof: %s)" % (hint, why)


class Context:
    """What judging a config path needs: the fixed table, the running
    binaries by inode, and whether --exec-version is on."""

    def __init__(self, fixed, procs=(), exec_version=False):
        self.fixed = fixed
        self.exec_version = exec_version
        self.known = {}
        for p in procs:
            if p.get("inode") and p.get("version") and not p.get("deleted"):
                self.known.setdefault(tuple(p["inode"]), p)


def judge_path(path, ctx, tool_uses_path=True):
    """Judge a Node path found in a pm2 entry, crontab or unit. The binary is
    not read: a running process that uses the same file gives its version,
    otherwise the path is a hint. Pinned means the path itself names one
    install, so it will not follow the next upgrade. npm, npx and corepack
    start with `#!/usr/bin/env node`, so run directly they use the first node
    on PATH, not the one next to them (tool_uses_path=False when pm2 passes
    the interpreter itself)."""
    node = node_for(path)
    pin = pinned_version(path)
    try:
        st = os.stat(node)
    except OSError:
        reason = "%s does not exist" % node
        if pin:
            reason += "; the path names %s (%s)" % (pin, classify(pin, ctx.fixed)[0])
        return {"path": path, "node": node, "pinned": bool(pin), "version": pin,
                "status": "missing", "reason": reason}
    hint = pin or pinned_version(os.path.realpath(node))
    version = None
    running = ctx.known.get((st.st_dev, st.st_ino))
    if running:
        version = running["version"]
        status, reason = running["status"], "%s (same file as running pid %d)" % (
            running["reason"], running["pid"])
    elif ctx.exec_version:
        version, why = exec_version_hardened(node, (st.st_dev, st.st_ino))
        if version:
            status, reason = classify(version, ctx.fixed)
        else:
            status, reason = hint_status(hint, ctx.fixed, "--exec-version refused: %s" % why)
    else:
        status, reason = hint_status(hint, ctx.fixed)
    if tool_uses_path and os.path.basename(path) in ("npm", "npx", "corepack") \
            and status == "patched":
        status = "unknown"
        reason += ("; %s runs on the first `node` on the PATH it is started with, "
                   "which this line does not show" % os.path.basename(path))
    return {"path": path, "node": node, "pinned": bool(pin), "version": version or hint,
            "from_path": not version, "status": status, "reason": reason}


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


def scan_text_sources(sources, ctx):
    """sources: (label, text) or (label, None, error) for a file that should
    have been read but could not be: that is unknown, not clean."""
    results = []
    for src in sources:
        label, text = src[0], src[1]
        if text is None:
            results.append({"where": label, "path": None, "node": None, "pinned": False,
                            "version": None, "status": "unknown",
                            "reason": "cannot read: %s" % src[2]})
            continue
        for no, p in find_node_paths(text):
            r = judge_path(p, ctx)
            r["where"] = "%s:%d" % (label, no)
            results.append(r)
        # EnvironmentFile= is never followed. For units that run Node, list it
        # as not read, so the operator can check it for PATH or node paths.
        if NODEISH_RE.search(text):
            for m in ENV_FILE_RE.finditer(text):
                no = text.count("\n", 0, m.start()) + 1
                results.append({"where": "%s:%d" % (label, no), "path": m.group(1).strip(),
                                "node": None, "pinned": False, "version": None,
                                "status": "unknown", "reason": "EnvironmentFile not read: check "
                                "it for PATH or node paths"})
    return results


def read_unit(path, sources, limit=MAX_READ):
    """Append (path, text) for a unit file owned by root or by us, or
    (path, None, error) when it cannot be read. Units owned by anyone else
    are skipped: as root, reading them would let their owner point us at
    files. A file above the limit is an error, never silently cut short."""
    try:
        fd, st = open_pinned(path)
    except OSError as e:
        sources.append((path, None, e.strerror or str(e)))
        return
    try:
        if st.st_uid not in (0, os.geteuid()):
            return
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        sources.append((path, None, "larger than %d MB" % (limit >> 20)))
    else:
        sources.append((path, data.decode("utf-8", "replace")))


def crontab_sources(args):
    """`crontab -l` of the user running the script. (--crontab-file reads a
    copy instead, for tests and offline review.)"""
    sources = []
    if args.crontab_file:
        for f in args.crontab_file:
            try:
                sources.append((f, safe_read(f)))
            except OSError as e:
                sources.append((f, None, e.strerror or str(e)))
        return sources
    if shutil.which("crontab"):
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
            label = "crontab -l (%s)" % username(os.geteuid())
            if out.returncode == 0:
                sources.append((label, out.stdout))
            elif "no crontab" not in (out.stderr or "").lower():
                sources.append((label, None, "exit %d: %s" % (out.returncode, " ".join(
                    (out.stderr or "").strip().splitlines()[:1]))))
        except (OSError, subprocess.SubprocessError) as e:
            sources.append(("crontab -l", None, str(e)))
    return sources


ENV_FILE_RE = re.compile(r"^\s*EnvironmentFile\s*=\s*(.+?)\s*$", re.M)
# A unit runs Node when an Exec*= or Environment= line names node, npm, npx
# or pm2 as a command or path (a Description that says "node" does not count).
NODEISH_RE = re.compile(r"^\s*(Exec\w*|Environment)\s*=.*(^|[\s/=\"'])(node|nodejs|npm|npx|pm2)"
                        r"([\s\"';]|$)", re.M)

SYSTEMD_DIRS = ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
                "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/systemd/user",
                "~/.config/systemd/user"]
UNIT_PATTERNS = ("*.service", "*.service.d/*.conf", "*.timer")


def systemd_sources(dirs):
    """Unit files and drop-ins in the usual directories. Nothing they refer
    to (EnvironmentFile=, scripts) is read."""
    sources, seen = [], set()
    for d in dirs:
        d = os.path.expanduser(d)
        for pat in UNIT_PATTERNS:
            for f in sorted(glob.glob(os.path.join(d, pat))):
                real = os.path.realpath(f)
                if real in seen or os.path.islink(f) or not os.path.isfile(f):
                    # Symlinked units are skipped (an enabled unit's real file
                    # sits in one of these directories); so is anything that
                    # is not a regular file.
                    continue
                seen.add(real)
                read_unit(f, sources)
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


def installed_versions(homes, ctx):
    """Node installs kept by version managers, for information: nothing is
    read, versions come from directory names or from a running process that
    uses the same binary. They do not affect the exit code."""
    def label(path):
        try:
            st = os.stat(path)
        except OSError:
            return {"version": pinned_version(path), "source": "missing", "status": "missing"}
        running = ctx.known.get((st.st_dev, st.st_ino))
        if running:
            return {"version": running["version"], "source": "running", "status": running["status"]}
        hint = pinned_version(path) or pinned_version(os.path.realpath(path))
        return {"version": hint, "source": "from path", "status": hint_status(hint, ctx.fixed)[0]}

    out, seen = [], set()
    for home in homes:
        nvm = os.environ.get("NVM_DIR") if home == os.path.expanduser("~") else None
        fnms = [os.environ.get("FNM_DIR")] if home == os.path.expanduser("~") else []
        fnms += [os.path.join(home, ".local/share/fnm"), os.path.join(home, ".fnm")]
        for name, pattern, alias in MANAGERS:
            for fnm in ([d for d in fnms if d] if name == "fnm" else [None]):
                ctx_dirs = {"home": home, "nvm": nvm or os.path.join(home, ".nvm"), "fnm": fnm}
                pat = pattern.format(**ctx_dirs)
                if pat in seen:
                    continue
                seen.add(pat)
                bins = sorted(glob.glob(pat))
                if not bins:
                    continue
                default = None
                if alias:
                    a = alias.format(**ctx_dirs)
                    if os.path.islink(a):
                        target = os.path.realpath(a)
                        node = next((c for c in (os.path.join(target, "bin", "node"),
                                                 os.path.join(target, "installation", "bin", "node"))
                                     if os.path.exists(c)), os.path.join(target, "bin", "node"))
                        default = label(node)
                    elif os.path.isfile(a):
                        default = {"version": None, "source": "alias file %s not read" % a,
                                   "status": "unknown"}
                out.append({"manager": name, "where": os.path.dirname(pat.split("*")[0].rstrip("/")),
                            "versions": [label(b) for b in bins], "default": default})
    shell = None
    which = shutil.which("node")
    if which:
        shell = dict(label(which), path=which, real=os.path.realpath(which))
    return out, shell


# ---------------------------------------------------------------- pm2

def resolve_on_path(path_value, cwd=None, skip_ephemeral=False, name="node"):
    """First executable `name` on a saved PATH, like execvp would find it.
    Empty and relative entries are resolved against the app's cwd. With
    skip_ephemeral, fnm multishell dirs (gone after a reboot) are skipped,
    because that is what a resurrected app will see. Returns (dir, notes)."""
    notes = []
    for d in (path_value or "").split(":"):
        if not d or not d.startswith("/"):
            if not cwd:
                notes.append("relative PATH entry %r skipped: no cwd" % d)
                continue
            d = os.path.join(cwd, d)
        if skip_ephemeral and FNM_MULTISHELL_RE.search(d):
            notes.append("skipped %s: an fnm multishell dir does not survive a reboot" % d)
            continue
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return d, notes
    return None, notes


def pm2_entry(entry, ctx, procs_by_pid, table, daemon=None, saved=False):
    env = entry.get("pm2_env", entry) if isinstance(entry, dict) else None
    if not isinstance(env, dict):
        return {"name": "?", "status_pm2": None, "pid": None, "cluster": False, "interpreter": "",
                "script": "", "running": [], "status": "unknown",
                "findings": [{"what": "entry", "path": None, "pinned": False, "version": None,
                              "status": "unknown", "reason": "malformed pm2 entry"}]}
    text = lambda v: v if isinstance(v, str) else ""  # noqa: E731
    name = text(env.get("name")) or text(entry.get("name")) or "?"
    interp = text(env.get("exec_interpreter"))
    script = text(env.get("pm_exec_path"))
    sub_env = env.get("env") if isinstance(env.get("env"), dict) else {}
    path_value = text(env.get("PATH")) or text(sub_env.get("PATH"))
    cwd = text(env.get("pm_cwd")) or text(env.get("cwd")) or None
    cluster = env.get("exec_mode") == "cluster_mode"
    bare = interp in ("node", "nodejs")
    findings = []

    if cluster:
        # Cluster workers are forked by the daemon with its own
        # process.execPath: interpreter and PATH do not choose their binary.
        if daemon and daemon.get("version"):
            reason = "cluster mode runs on the daemon's Node: %s" % daemon.get("reason")
            if saved:
                reason += "; after a reboot, the Node that starts pm2 (startup unit PATH) decides"
            findings.append({"what": "daemon node", "path": daemon.get("exe"), "pinned": False,
                             "version": daemon.get("version"), "status": daemon["status"],
                             "reason": reason})
        else:
            findings.append({"what": "daemon node", "path": None, "pinned": False, "version": None,
                             "status": "unknown", "reason": "cluster mode runs on the Node that "
                             "starts the pm2 daemon, which could not be determined"})
    elif interp.startswith("/"):
        r = judge_path(interp, ctx, tool_uses_path=False)
        r["what"] = "interpreter"
        findings.append(r)
    if script.startswith("/") and pinned_version(script) and re.search(r"node", script, re.I):
        r = judge_path(script, ctx, tool_uses_path=False)
        r["what"] = "script"
        findings.append(r)
    running = []
    pid = entry.get("pid") or env.get("pid")
    if isinstance(pid, int) and pid:
        tree = {pid} | descendants(pid, table)
        running = [procs_by_pid[p] for p in sorted(tree) if p in procs_by_pid]
    else:
        pid = None
    # The saved PATH decides which node a bare `node` interpreter, a
    # `#!/usr/bin/env node` script or a child process gets. It does not
    # matter for an entry that runs Python or bash and starts no Node.
    other_interp = (interp.startswith("/") and os.path.basename(interp) not in ("node", "nodejs")) \
        or (interp and not interp.startswith("/") and not bare and interp != "none")
    d, notes = resolve_on_path(path_value, cwd, skip_ephemeral=saved,
                               name="nodejs" if interp == "nodejs" else "node")
    if other_interp and not running:
        pass
    elif d:
        r = judge_path(os.path.join(d, "nodejs" if interp == "nodejs" else "node"), ctx)
        r["what"] = "PATH node"
        if FNM_MULTISHELL_RE.search(d):
            r["reason"] += "; fnm multishell dir: gone after a reboot"
        if notes:
            r["reason"] += "; " + "; ".join(notes)
            if any("no cwd" in n for n in notes) and r["status"] == "patched":
                r["status"] = "unknown"
        findings.append(r)
    elif bare and not cluster:
        findings.append({"what": "PATH node", "path": None, "pinned": False, "version": None,
                         "status": "unknown",
                         "reason": "no node on the saved PATH" + ("; " + "; ".join(notes) if notes else "")})
    statuses = [f["status"] for f in findings] + [p["status"] for p in running]
    return {"name": name, "status_pm2": text(env.get("status")), "pid": pid, "cluster": cluster,
            "interpreter": interp, "script": script, "findings": findings, "running": running,
            "status": worst(statuses) if statuses else "none"}


def pm2_homes(args):
    if args.pm2_home:
        return [os.path.expanduser(h) for h in args.pm2_home]
    homes = [os.environ.get("PM2_HOME") or os.path.expanduser("~/.pm2")]
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


def find_pm2_daemon(home, proc_root, table):
    """The pid of the pm2 daemon for PM2_HOME, from /proc: a process of ours
    whose title is `PM2 vX.Y.Z: God Daemon (<PM2_HOME>)`."""
    want = b"God Daemon (" + os.fsencode(home.rstrip("/")) + b")"
    for pid, row in sorted(table.items()):
        if row.get("uid") != os.geteuid():
            continue
        try:
            title = read_proc(os.path.join(proc_root, str(pid), "cmdline"), "rb").rstrip(b"\0")
        except OSError:
            continue
        if title.startswith(b"PM2 v") and title.endswith(want):
            return pid
    return None


def pm2_live(home, args, proc_root, table):
    """`pm2 jlist` for our own PM2_HOME, only when its daemon is running
    (jlist would otherwise start one). The pm2 CLI is the one thing on the
    host the script runs: your own pm2, as you, and only when it is owned by
    you or root and not writable by group or others."""
    if args.pm2_jlist_file:
        try:
            data = load_json_list(safe_read(args.pm2_jlist_file, limit=64 << 20))
        except OSError as e:
            return None, "FAIL: cannot read %s: %s" % (args.pm2_jlist_file, e.strerror or e)
        return data, (None if data is not None else "FAIL: no JSON list in %s" % args.pm2_jlist_file)
    if find_pm2_daemon(home, proc_root, table) is None:
        return None, "no pm2 daemon running for this PM2_HOME"
    pm2 = args.pm2_bin or shutil.which("pm2")
    if not pm2:
        return None, "FAIL: pm2 daemon runs but no pm2 CLI was found"
    try:
        cli = os.stat(os.path.realpath(pm2))
    except OSError as e:
        return None, "FAIL: cannot stat the pm2 CLI: %s" % e.strerror
    if not trusted_owner_ok(cli, os.geteuid()):
        return None, "FAIL: pm2 CLI %s is %s: not run, live list skipped" % (
            pm2, untrusted_reason(cli, os.geteuid()))
    env = dict(os.environ, PM2_HOME=home)
    try:
        out = subprocess.run([pm2, "jlist"], capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "FAIL: pm2 jlist failed: %s" % e
    if out.returncode != 0:
        return None, "FAIL: pm2 jlist exited %d" % out.returncode
    data = load_json_list(out.stdout)
    return data, (None if data is not None else "FAIL: pm2 jlist gave no JSON")


def pm2_daemon(home, proc_root, procs_by_pid, table):
    dpid = find_pm2_daemon(home, proc_root, table)
    if dpid is None:
        return None
    return procs_by_pid.get(dpid) or {"pid": dpid, "status": "unknown",
                                      "reason": "pid %d is not a visible Node process" % dpid}


# ---------------------------------------------------------------- containers

def container_checks(cli, fixed, run_exec=True):
    """Running containers of one CLI. By default it asks the container to run
    `node --version` (docker exec), which runs the container's own binary
    inside the container, never on the host."""
    results = []
    try:
        out = subprocess.run([cli, "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "%s ps failed: %s" % (cli, e)
    if out.returncode != 0:
        return None, "%s ps failed: %s" % (cli, " ".join((out.stderr or "").strip().splitlines()[:1]))
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        cid, name, image = parts[0], parts[1], parts[2]
        version, exec_error, no_node = None, None, False
        if run_exec:
            try:
                r = subprocess.run([cli, "exec", "-e", "NODE_OPTIONS=", cid, "node", "--version"],
                                   capture_output=True, text=True, timeout=30)
                first = (r.stdout or "").strip().splitlines()
                if r.returncode == 0 and first and VERSION_RE.match(first[0]):
                    version = first[0].strip()
                elif re.search(r'"node": executable file not found|executable file .{0,2}node.{0,2} not found',
                                   r.stderr or ""):
                    no_node = True  # docker and podman both say this when node is not on PATH
                else:
                    exec_error = "exec exit %d: %s" % (r.returncode, " ".join(
                        (r.stderr or r.stdout or "").strip().splitlines()[:1]))
            except (OSError, subprocess.SubprocessError) as e:
                exec_error = "exec failed: %s" % e
        env_version = None
        try:
            r = subprocess.run([cli, "inspect", "--format",
                                "{{range .Config.Env}}{{println .}}{{end}}", cid],
                               capture_output=True, text=True, timeout=30)
            for env_line in r.stdout.splitlines():
                if env_line.startswith("NODE_VERSION="):
                    env_version = env_line.split("=", 1)[1].strip()
            if r.returncode != 0 and not version:
                exec_error = exec_error or "inspect exit %d" % r.returncode
        except (OSError, subprocess.SubprocessError) as e:
            exec_error = exec_error or "inspect failed: %s" % e
        if version:
            status, reason = classify(version, fixed)
            if env_version and env_version.lstrip("v") != version.lstrip("v"):
                reason += "; image ENV says NODE_VERSION=%s" % env_version
        elif exec_error:
            status, reason = "unknown", exec_error
        elif not run_exec and env_version:
            status, reason = "unknown", ("image ENV says NODE_VERSION=%s (a hint, not proof); "
                                         "drop --no-container-exec to ask the container" % env_version)
        elif not run_exec:
            status, reason = "unknown", "not checked (--no-container-exec)"
        elif no_node and env_version:
            status, reason = "unknown", ("no node on the container PATH; image ENV says "
                                         "NODE_VERSION=%s" % env_version)
        else:
            continue  # no node on the container PATH and no NODE_VERSION: not a Node container
        results.append({"id": cid[:12], "name": name, "image": image, "version": version,
                        "cli": os.path.basename(cli), "status": status, "reason": reason})
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
        # The first directory below a non-hidden dir in a home is usually a
        # project or app name: /home/USER/projects/<name>/...
        s = re.sub(r"(/home/USER/[^./\s:][^/\s:]*/)([^/\s:]+)",
                   lambda m: m.group(1) + self.name(m.group(2)), s)
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
        w("  %d processes of other users not inspected: run the script as their owner\n"
          % rep["hidden"])

    for sec in rep["pm2"]:
        w("\npm2 %s (%s)\n" % (sec["kind"], red(sec["source"])))
        if sec.get("error"):
            if sec.get("error_status"):
                w("  %-13s %s\n" % (tag(sec["error_status"]), red(sec.get("error_text") or sec["error"])))
            else:
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
            w("      installed: %s\n" % ", ".join("%s (%s)" % (v["version"] or "?", v["source"])
                                                for v in m["versions"]))
            if m["default"]:
                d = m["default"]
                w("      default alias -> %s (%s)\n" % (d["version"] or "?", red(d["source"])))
        if inst.get("shell"):
            sh = inst["shell"]
            w("  `node` on this shell's PATH -> %s (%s) %s\n" % (
                sh.get("version") or "?", sh["source"], red(sh["real"])))
        w("  for information only: these do not change the exit code\n")

    for key, title in (("cron", "Crontab"), ("systemd", "systemd units")):
        items = rep.get(key)
        if items is None:
            continue
        w("\n%s: absolute Node paths\n" % title)
        if not items:
            w("  none found\n")
        for r in items:
            w("  %-13s %s\n" % (tag(r["status"]), red(r["where"])))
            if r.get("path"):
                w("      %s -> %s%s%s\n" % (red(r["path"]), r.get("version") or "?",
                                           " (from path)" if r.get("from_path") and r.get("version") else "",
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
    for err in rep["containers"].get("errors", []):
        w("  %-13s %s\n" % (tag("unknown"), red(err)))
    for c in rep["containers"].get("items", []):
        w("  %-13s %s %s node %s\n" % (tag(c["status"]), red(c["name"]), red(c["image"]),
                                       c.get("version") or "?"))
        if c["status"] != "patched":
            w("      why: %s\n" % red(c["reason"]))

    w("\nresult: %s (exit %d)\n" % (rep["result"], rep["exit"]))


# ---------------------------------------------------------------- main

def build_report(args):
    fixed = parse_fixed(args.fixed)
    inspector = BinaryInspector(exec_version=args.exec_version)
    notes = []
    if os.geteuid() != 0:
        notes.append("covers the processes, crontab and pm2 of %s; run it as each user that "
                     "owns Node processes" % username(os.geteuid()))

    table = proc_table(args.proc_root)
    procs, hidden = scan_processes(args.proc_root, inspector, fixed, table)
    ctx = Context(fixed, procs, exec_version=args.exec_version)
    by_pid = {p["pid"]: p for p in procs}
    for p in procs:
        p["parents"] = ancestry(p["pid"], table, by_pid)

    pm2_sections = []
    if not args.no_pm2:
        homes = pm2_homes(args) if not args.pm2_jlist_file else [args.pm2_home[0] if args.pm2_home else "(file)"]
        for home in homes:
            live, err = pm2_live(home, args, args.proc_root, table)
            if live is not None or err:
                daemon = pm2_daemon(home, args.proc_root, by_pid, table)
                sec = {"kind": "live list", "source": "pm2 jlist, PM2_HOME=%s" % home,
                       "error": err if live is None else None, "daemon": daemon,
                       "error_status": "unknown" if (live is None and err and err.startswith("FAIL")) else None,
                       "error_text": (err or "")[len("FAIL: "):] if (err or "").startswith("FAIL: ") else err,
                       "entries": [pm2_entry(e, ctx, by_pid, table, daemon)
                                   for e in (live or [])]}
                pm2_sections.append(sec)

    rep = {"release": RELEASE, "fixed": fixed, "notes": notes, "processes": procs,
           "hidden": hidden, "pm2": pm2_sections, "containers": {}}
    if not args.no_installs:
        managers, shell = installed_versions([os.path.expanduser("~")], ctx)
        rep["installs"] = {"managers": managers, "shell": shell}
    if not args.no_cron:
        rep["cron"] = scan_text_sources(crontab_sources(args), ctx)
    if not args.no_systemd:
        sd = scan_text_sources(systemd_sources(args.systemd_dir or SYSTEMD_DIRS), ctx)
        for r in sd:
            unit_file = r["where"].rsplit(":", 1)[0]
            if "pm2" in os.path.basename(unit_file) and not args.systemd_dir \
                    and unit_file.endswith(".service"):
                r["unit_state"] = pm2_unit_state(unit_file)
        rep["systemd"] = sd

    rep["containers"] = {"error": None, "errors": [], "items": []}
    if args.no_containers:
        rep["containers"]["error"] = "skipped"
    else:
        clis = [args.container_cli] if args.container_cli else \
            [c for c in (shutil.which("docker"), shutil.which("podman")) if c]
        if not clis:
            rep["containers"]["error"] = "no docker or podman CLI found"
        for cli in clis:
            items, err = container_checks(cli, fixed, run_exec=not args.no_container_exec)
            rep["containers"]["items"] += items or []
            if err:
                rep["containers"]["errors"].append(err)

    statuses = [p["status"] for p in procs]
    for sec in pm2_sections:
        statuses += [e["status"] for e in sec["entries"]]
        if sec.get("daemon"):
            statuses.append(sec["daemon"]["status"])
        if sec.get("error_status"):
            statuses.append(sec["error_status"])
    if rep["containers"]["errors"]:
        statuses.append("unknown")
    for key in ("cron", "systemd"):
        statuses += [r["status"] for r in rep.get(key) or []]
    statuses += [c["status"] for c in rep["containers"].get("items", [])]
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
    ap.add_argument("--exec-version", action="store_true",
                    help="run `node --version` on Node binaries named in pm2 entries, crontabs and "
                         "units (and as a cross-check for processes), only when root (or you, when "
                         "not root) owns the file and every directory above it")
    ap.add_argument("--no-pm2", action="store_true")
    ap.add_argument("--no-cron", action="store_true")
    ap.add_argument("--no-systemd", action="store_true")
    ap.add_argument("--no-containers", action="store_true")
    ap.add_argument("--no-container-exec", action="store_true",
                    help="do not run `node --version` inside containers; image metadata only")
    ap.add_argument("--no-installs", action="store_true", help="skip nvm/fnm/... install listing")
    ap.add_argument("--container-cli", help="docker or podman binary (default: auto)")
    ap.add_argument("--pm2-bin", help="pm2 CLI (default: pm2 on PATH)")
    ap.add_argument("--pm2-home", action="append", help="PM2_HOME to inspect (repeatable)")
    # For tests and offline review of files copied from a host:
    ap.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    ap.add_argument("--pm2-jlist-file", help=argparse.SUPPRESS)
    ap.add_argument("--crontab-file", action="append", help=argparse.SUPPRESS)
    ap.add_argument("--systemd-dir", action="append", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        rep = clean_tree(build_report(args))
    except ValueError as e:
        ap.error(clean(str(e)))
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
