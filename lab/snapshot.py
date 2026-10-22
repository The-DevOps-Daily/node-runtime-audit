#!/usr/bin/env python3
"""Print what a pm2 lab daemon is really running.

Reads `pm2 jlist` JSON on stdin and the daemon pid file, then walks /proc
from each app's pid down through its children and prints the real binary
(readlink /proc/<pid>/exe) and its version for every process. Used by
pm2-pin-lab.sh; it only reads.
"""

import json
import os
import re
import subprocess
import sys

HOME_RE = re.compile(r"/home/[^/\s]+")
VERSIONS = {}


LAB_APP = sys.argv[2] if len(sys.argv) > 2 else None


def tidy(path):
    path = path or ""
    if LAB_APP:
        path = path.replace(LAB_APP, "<app>")
    return HOME_RE.sub("/home/USER", path)


def short(path):
    """Shorten a versioned install path to '<install vX.Y.Z>/bin/node'."""
    path = tidy(path)
    m = re.search(r"^(.*?/)(v\d+\.\d+\.\d+)(/.*)$", path)
    if m:
        return "<%s>%s" % (m.group(2), m.group(3).replace("/installation", ""))
    return path


def version_of(exe):
    if exe in VERSIONS:
        return VERSIONS[exe]
    if not re.search(r"/(node|nodejs)$", exe):
        VERSIONS[exe] = None
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True,
                             timeout=10, env={"PATH": "/usr/bin:/bin"}).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = "?"
    VERSIONS[exe] = out
    return out


def children_map():
    kids = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            stat = open("/proc/%s/stat" % pid).read()
        except OSError:
            continue
        ppid = int(stat[stat.rfind(")") + 2:].split()[1])
        kids.setdefault(ppid, []).append(int(pid))
    return kids


def describe(pid):
    try:
        exe = os.readlink("/proc/%d/exe" % pid)
    except OSError:
        return None
    try:
        argv = open("/proc/%d/cmdline" % pid, "rb").read().split(b"\0")
        cmd = " ".join(os.path.basename(a.decode(errors="replace")) if i == 0 else
                       a.decode(errors="replace") for i, a in enumerate(argv[:3]) if a)
    except OSError:
        cmd = "?"
    ver = version_of(exe)
    what = ("node %s" % ver) if ver else ("%s (not node)" % os.path.basename(exe))
    return "pid %-7d %-16s %-44s %s" % (pid, what, short(exe), tidy(cmd)[:60])


def walk(pid, kids, depth):
    line = describe(pid)
    if line is None:
        return
    print("  " + "  " * depth + line)
    for k in sorted(kids.get(pid, [])):
        walk(k, kids, depth + 1)


def main():
    pm2_home = sys.argv[1]
    raw = sys.stdin.read()
    apps = json.loads(raw[raw.find("["):]) if "[" in raw else []
    try:
        dpid = int(open(os.path.join(pm2_home, "pm2.pid")).read().strip())
        dexe = os.readlink("/proc/%d/exe" % dpid)
        print("daemon     pid %-7d node %-10s %s" % (dpid, version_of(dexe), short(dexe)))
    except (OSError, ValueError):
        print("daemon     not running")
    kids = children_map()
    for app in apps:
        env = app.get("pm2_env", {})
        path = env.get("PATH") or env.get("env", {}).get("PATH", "")
        first_node_dir = next((d for d in path.split(":")
                               if d and os.path.isfile(os.path.join(d, "node"))), "")
        print("%-10s interpreter=%s  script=%s%s" % (
            app.get("name"), short(env.get("exec_interpreter")),
            short(env.get("pm_exec_path")),
            "  (cluster mode)" if env.get("exec_mode") == "cluster_mode" else ""))
        print("%-10s saved PATH finds node in %s" % ("", short(first_node_dir)))
        if app.get("pid"):
            walk(app["pid"], kids, 0)
        else:
            print("  (no pid, status %s)" % env.get("status"))


if __name__ == "__main__":
    main()
