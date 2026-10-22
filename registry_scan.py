#!/usr/bin/env python3
"""Which official `node` image tags ship a fixed Node, from registry metadata.

For each tag and platform it reads the image manifest and the image config
(a few KB of JSON each, checked against their sha256 digests) and takes the
Node version from ENV NODE_VERSION. It never downloads a layer.

Docker Hub counts each manifest GET against the anonymous pull limit, so the
platform digests come from the Hub tags API and each tag/platform costs one
counted request. Results go to results/registry-<UTC time>.json.

Usage: python3 registry_scan.py [--platform linux/amd64 --platform linux/arm64] [tag ...]
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from node_runtime_audit import FIXED_DEFAULT, classify, parse_fixed  # noqa: E402

DEFAULT_TAGS = [
    # supported lines, main variants
    "22", "22-slim", "22-alpine", "22-trixie-slim",
    "24", "24-slim", "24-alpine", "24-trixie-slim",
    "26", "26-slim", "26-alpine", "26-bookworm-slim",
    # moving aliases people pin to
    "latest", "lts", "lts-slim", "lts-alpine", "current-alpine", "alpine",
    # end-of-life lines: no fixed release will come
    "25", "25-alpine", "20", "20-alpine", "18", "18-alpine",
]
ACCEPT = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
UA = "node-runtime-audit registry_scan (+https://github.com/The-DevOps-Daily/node-runtime-audit)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def get(url, headers=None, timeout=30):
    """GET with manual redirects; Authorization is dropped when a redirect
    leaves the registry host (blobs are served from a CDN)."""
    hdrs = {"User-Agent": UA}
    hdrs.update(headers or {})
    origin = urllib.parse.urlsplit(url).netloc
    for _ in range(5):
        try:
            with OPENER.open(urllib.request.Request(url, headers=hdrs), timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if e.code in (301, 302, 303, 307, 308) and loc:
                url = urllib.parse.urljoin(url, loc)
                target = urllib.parse.urlsplit(url)
                if target.scheme != "https":
                    raise RuntimeError("refusing non-https redirect")
                if target.netloc != origin:
                    hdrs = {k: v for k, v in hdrs.items() if k.lower() != "authorization"}
                continue
            if e.code == 429:
                raise RuntimeError("HTTP 429 rate limited, Retry-After %s" % e.headers.get("Retry-After"))
            return e.code, dict(e.headers), e.read()
    raise RuntimeError("too many redirects")


def token():
    _, _, body = get("https://auth.docker.io/token?service=registry.docker.io"
                     "&scope=repository:library/node:pull")
    return json.loads(body)["token"]


def hub_tag(tag):
    status, _, body = get("https://hub.docker.com/v2/repositories/library/node/tags/%s"
                          % urllib.parse.quote(tag))
    if status != 200:
        return None
    return json.loads(body)


def platform_digest(hub, platform):
    os_name, arch = platform.split("/")[:2]
    for img in hub.get("images", []):
        if img.get("os") == os_name and img.get("architecture") == arch \
                and img.get("variant") in (None, "", "v8"):
            return img.get("digest"), img.get("last_pushed")
    return None, None


def read_config(tok, digest):
    """Manifest by digest, then config blob; both checked against sha256."""
    auth = {"Authorization": "Bearer %s" % tok}
    status, headers, body = get("https://registry-1.docker.io/v2/library/node/manifests/%s" % digest,
                                dict(auth, Accept=ACCEPT))
    if status != 200:
        raise RuntimeError("manifest HTTP %s" % status)
    if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
        raise RuntimeError("manifest digest mismatch")
    remaining = headers.get("ratelimit-remaining") or headers.get("RateLimit-Remaining")
    cfg_digest = json.loads(body)["config"]["digest"]
    status, _, cfg = get("https://registry-1.docker.io/v2/library/node/blobs/%s" % cfg_digest, auth)
    if status != 200:
        raise RuntimeError("config HTTP %s" % status)
    if "sha256:" + hashlib.sha256(cfg).hexdigest() != cfg_digest:
        raise RuntimeError("config digest mismatch")
    return json.loads(cfg), remaining


def scan(tags, platforms, fixed):
    tok, tok_at = token(), time.time()
    rows = []
    for tag in tags:
        hub = hub_tag(tag)
        for platform in platforms:
            row = {"tag": tag, "platform": platform}
            rows.append(row)
            if not hub:
                row.update(status="unknown", reason="tag not found on Docker Hub")
                continue
            digest, pushed = platform_digest(hub, platform)
            row.update(digest=digest, hub_last_pushed=pushed, tag_last_pushed=hub.get("tag_last_pushed"))
            if not digest:
                row.update(status="unknown", reason="no %s image for this tag" % platform)
                continue
            if time.time() - tok_at > 240:
                tok, tok_at = token(), time.time()
            try:
                cfg, remaining = read_config(tok, digest)
            except (RuntimeError, ValueError, KeyError, OSError) as e:
                row.update(status="unknown", reason=str(e))
                continue
            env = dict(e.split("=", 1) for e in (cfg.get("config") or {}).get("Env") or [] if "=" in e)
            version = env.get("NODE_VERSION")
            status, reason = classify(version, fixed)
            row.update(node_version=version, created=cfg.get("created"), status=status,
                       reason=reason, ratelimit_remaining=remaining)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tags", nargs="*", default=DEFAULT_TAGS)
    ap.add_argument("--platform", action="append", help="default linux/amd64 and linux/arm64")
    ap.add_argument("--fixed", default=FIXED_DEFAULT)
    ap.add_argument("--out-dir", default=os.path.join(HERE, "results"))
    args = ap.parse_args(argv)
    fixed = parse_fixed(args.fixed)
    platforms = args.platform or ["linux/amd64", "linux/arm64"]
    started = datetime.datetime.now(datetime.timezone.utc)
    rows = scan(args.tags or DEFAULT_TAGS, platforms, fixed)
    finished = datetime.datetime.now(datetime.timezone.utc)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out = {"scanned_from": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "scanned_to": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "fixed": {str(k): "v%d.%d.%d" % v for k, v in fixed.items()},
           "method": "Docker Hub tags API for platform digests; registry manifest and config "
                     "blob by digest (sha256 checked); ENV NODE_VERSION; no layers pulled",
           "rows": rows}
    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, "registry-%s.json" % stamp)
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("official node images, scanned %s to %s UTC" % (out["scanned_from"], out["scanned_to"]))
    print("%-16s %-12s %-10s %-11s %-20s %s" % ("tag", "platform", "node", "status", "image built", "digest"))
    for r in rows:
        print("%-16s %-12s %-10s %-11s %-20s %s" % (
            r["tag"], r["platform"].split("/")[1], r.get("node_version") or "?", r["status"],
            (r.get("created") or "")[:19], (r.get("digest") or "")[:19]))
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("summary: %s" % ", ".join("%s %d" % kv for kv in sorted(counts.items())))
    print("written: %s" % os.path.relpath(path, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
