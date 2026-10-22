#!/usr/bin/env python3
"""Summarize a registry scan: hours from the Node.js release to each image's
build time and to Docker Hub's last-pushed time for that platform image.

Usage: python3 scripts/summarize_registry.py results/registry-<time>.json

The reference time is when the fixed binaries appeared on nodejs.org/dist
(SHASUMS256.txt at 10:32 to 10:36 UTC on 2026-10-21; see SOURCES.md). Build
time is the image config's `created`. Docker Hub's last-pushed time is
metadata about the platform image and is not proof of when a tag first served
it.
"""

import datetime
import json
import sys

RELEASE = datetime.datetime(2026, 10, 21, 10, 36, tzinfo=datetime.timezone.utc)


def ts(s):
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        tz = rest[rest.find("+"):] if "+" in rest else ""
        s = head + tz
    return datetime.datetime.fromisoformat(s)


def hours(t):
    return (t - RELEASE).total_seconds() / 3600 if t else None


def main(path):
    data = json.load(open(path))
    print("scan %s to %s UTC; reference: fixed binaries on nodejs.org/dist by %s UTC"
          % (data["scanned_from"], data["scanned_to"], RELEASE.strftime("%Y-%m-%d %H:%M")))
    groups = {}
    for r in data["rows"]:
        if r.get("status") != "patched":
            continue
        family = "alpine" if "alpine" in r["tag"] else "debian"
        key = (family, r["platform"])
        built, pushed = hours(ts(r.get("created"))), hours(ts(r.get("hub_last_pushed")))
        groups.setdefault(key, []).append((built, pushed))
    print("%-8s %-12s %-6s %-22s %s" % ("family", "platform", "rows", "built (h after)", "hub last pushed (h after)"))
    for (family, platform), vals in sorted(groups.items()):
        b = [v[0] for v in vals if v[0] is not None]
        p = [v[1] for v in vals if v[1] is not None]
        print("%-8s %-12s %-6d %-22s %s" % (family, platform, len(vals),
                                           "%.1f to %.1f" % (min(b), max(b)),
                                           "%.1f to %.1f" % (min(p), max(p)) if p else "?"))
    eol = sorted({(r["tag"], r.get("node_version"), (r.get("created") or "")[:10])
                  for r in data["rows"] if r.get("status") == "vulnerable"})
    print("vulnerable (no fixed release for the line):")
    for tag, ver, built in eol:
        print("  node:%-10s %-8s built %s" % (tag, ver, built))
    print("unknown: %d" % sum(1 for r in data["rows"] if r.get("status") == "unknown"))


if __name__ == "__main__":
    main(sys.argv[1])
