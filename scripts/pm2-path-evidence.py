#!/usr/bin/env python3
"""Evidence for the post, not part of the audit: which Node install each pm2
app's PATH starts with, in the running processes and in the saved list.

Prints only the first PATH entry that holds a `node`, never other variables.
Run as the user that owns pm2. Usage: scripts/pm2-path-evidence.py [PM2_HOME]
"""
import json
import os
import re
import sys

HOME_RE = re.compile(r"/home/[^/\s:]+")


def first_node_dir(path_value):
    for d in (path_value or "").split(":"):
        if d.startswith("/") and os.path.isfile(os.path.join(d, "node")):
            return HOME_RE.sub("/home/USER", d)
    return None


def main():
    import datetime
    print("# %s" % datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    home = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.pm2")
    dump = os.path.join(home, "dump.pm2")
    print("# saved list: %s" % HOME_RE.sub("/home/USER", dump))
    with open(dump) as f:
        saved = json.load(f)
    for i, app in enumerate(saved, 1):
        env = app.get("env") if isinstance(app.get("env"), dict) else {}
        print("app-%d  saved PATH starts with node in: %s" % (
            i, first_node_dir(app.get("PATH") or env.get("PATH"))))
    print("# processes the pm2 daemon started (PATH from /proc/<pid>/environ)")
    want = b"God Daemon (" + os.fsencode(home) + b")"
    daemon, children = None, []
    for name in sorted(os.listdir("/proc"), key=lambda n: (len(n), n)):
        if not name.isdigit():
            continue
        try:
            title = open("/proc/%s/cmdline" % name, "rb").read().rstrip(b"\0")
            stat = open("/proc/%s/stat" % name).read()
        except OSError:
            continue
        ppid = int(stat[stat.rfind(")") + 2:].split()[1])
        if title.startswith(b"PM2 v") and title.endswith(want):
            daemon = int(name)
        children.append((int(name), ppid))
    for pid, ppid in children:
        if daemon is None or ppid != daemon:
            continue
        try:
            raw = open("/proc/%d/environ" % pid, "rb").read().split(b"\0")
        except OSError:
            print("pid %d not readable" % pid)
            continue
        path = next((v[5:].decode() for v in raw if v.startswith(b"PATH=")), "")
        print("pid %d (child of the pm2 daemon) PATH starts with node in: %s" % (pid, first_node_dir(path)))


if __name__ == "__main__":
    main()
