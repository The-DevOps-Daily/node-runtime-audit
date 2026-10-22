"""Tests for node_runtime_audit.py. Run: python3 -m unittest discover -s tests -v

Each test builds a fake host: Node binaries that carry their version the way
official builds do (the embedded headers URL), a fake /proc tree, and pm2,
crontab, systemd and docker fixtures. The cases are the ones a config-only or
version-only check gets wrong.
"""

import contextlib
import io
import json
import os
import shutil
import signal
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import node_runtime_audit as nra  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
FIXED = nra.parse_fixed(nra.FIXED_DEFAULT)


def node_binary(path, version, extra=b"", mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    blob = b"\x7fELF" + b"\0" * 60
    if version:
        blob += b"https://nodejs.org/download/release/v%s/node-v%s-headers.tar.gz\0" % (
            version.encode(), version.encode())
    with open(path, "wb") as f:
        f.write(blob + extra + b"\0" * 64)
    os.chmod(path, mode)


def script_binary(path, prints, embedded=None, mode=0o755, marker=None):
    """A shell script posing as node. With marker, running it creates that
    file, so a test can prove it was never executed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    body = "#!/bin/sh\n"
    if marker:
        body += "touch '%s'\n" % marker
    body += "echo %s\n" % prints
    if embedded:
        body += "# node-v%s-headers.tar.gz\n" % embedded
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, mode)


def render(src, dst, root):
    with open(src) as f:
        text = f.read().replace("{ROOT}", root)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w") as f:
        f.write(text)
    return dst


class FakeHost:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="nra-test-")
        r = self.root
        self.old = os.path.join(r, "nvm/versions/node/v24.14.0/bin/node")
        self.new = os.path.join(r, "nvm/versions/node/v24.22.1/bin/node")
        node_binary(self.old, "24.14.0")
        node_binary(self.new, "24.22.1")
        for b in ("npm", "npx"):
            for d in (os.path.dirname(self.old), os.path.dirname(self.new)):
                with open(os.path.join(d, b), "w") as f:
                    f.write("#!/usr/bin/env node\n")
        pm2_bin = os.path.join(r, "nvm/versions/node/v24.14.0/lib/node_modules/pm2/bin/pm2")
        os.makedirs(os.path.dirname(pm2_bin))
        open(pm2_bin, "w").write("#!/usr/bin/env node\n")
        node_binary(os.path.join(r, "fnm/node-versions/v24.14.0/installation/bin/node"), "24.14.0")
        node_binary(os.path.join(r, "usr/bin/node"), "22.23.4")
        b = os.path.join(r, "bins")
        node_binary(os.path.join(b, "eol/node"), "20.19.0")
        node_binary(os.path.join(b, "pre/node"), "27.0.0-pre")
        node_binary(os.path.join(b, "distro/node"), None, extra=b"libnode.so.127\0")
        node_binary(os.path.join(b, "deleted/node (deleted)"), "24.14.0")
        node_binary(os.path.join(b, "container/node"), "26.12.1")
        node_binary(os.path.join(b, "brotli/node"), "24.22.1")
        self.marker = os.path.join(r, "EXECUTED")
        script_binary(os.path.join(b, "mismatch/node"), "v24.22.1", embedded="24.14.0",
                      marker=self.marker)
        script_binary(os.path.join(b, "execonly/node"), "v26.12.1", marker=self.marker)
        # No embedded string, but the install ships include/node/node_version.h
        script_binary(os.path.join(r, "hdr/node-v24.22.1/bin/node"), "v24.22.1", marker=self.marker)
        os.makedirs(os.path.join(r, "hdr/node-v24.22.1/include/node"))
        open(os.path.join(r, "hdr/node-v24.22.1/include/node/node_version.h"), "w").write(
            "#define NODE_MAJOR_VERSION 24\n#define NODE_MINOR_VERSION 22\n"
            "#define NODE_PATCH_VERSION 1\n#define NODE_VERSION_IS_RELEASE 1\n")
        # Only the directory name says a version: not proof
        script_binary(os.path.join(r, "opt/node-v26.12.1-linux-arm64/bin/node"), "v26.12.1",
                      marker=self.marker)
        node_binary(os.path.join(b, "bash"), None)
        node_binary(os.path.join(b, "systemd"), None)

        self.proc = os.path.join(r, "proc")
        os.makedirs(os.path.join(self.proc, "self/ns"))
        os.symlink("mnt:[1]", os.path.join(self.proc, "self/ns/mnt"))
        P = self.add_proc
        P(1, 0, "systemd", ["/sbin/init"], os.path.join(b, "systemd"))
        P(100, 1, "node", ["node", "old.js"], self.old)
        P(101, 1, "node", ["node", "new.js"], self.new)
        P(102, 1, "node", ["node", "replaced.js"], os.path.join(b, "deleted/node (deleted)"))
        P(103, 1, "node", ["node", "in-container.js"], os.path.join(b, "container/node"), mnt="mnt:[2]")
        P(104, 1, "bash", ["bash"], os.path.join(b, "bash"))
        P(105, 1, "node", ["node", "eol.js"], os.path.join(b, "eol/node"))
        P(106, 1, "node", ["node", "pre.js"], os.path.join(b, "pre/node"))
        P(107, 1, "node", ["/usr/bin/node", "distro.js"], os.path.join(b, "distro/node"))
        P(108, 1, "node", ["node", "--token=abc", "hidden.js"], self.new)
        P(109, 1, "node", ["node", "brotli.js"], os.path.join(b, "brotli/node"),
          maps="7f00-7f01 r-xp 0 b3:02 42 /usr/lib/aarch64-linux-gnu/libbrotlidec.so.1.1.0 (deleted)\n")
        P(110, 1, "node", ["node", "mismatch.js"], os.path.join(b, "mismatch/node"))
        P(111, 1, "node", ["node", "execonly.js"], os.path.join(b, "execonly/node"))
        P(112, 1, "node", ["node", "\x1b]0;pwned\x07evil.js", "\x1b[2J"], self.old)
        P(113, 1, "node", ["node", "hdr.js"], os.path.join(r, "hdr/node-v24.22.1/bin/node"))
        P(114, 1, "node", ["node", "named.js"],
          os.path.join(r, "opt/node-v26.12.1-linux-arm64/bin/node"))
        # pm2 trees
        P(300, 1, "PM2 v6.0.14: Go", ["PM2 v6.0.14: God Daemon"], self.old)
        P(200, 300, "node", ["node", "/srv/api/server.js"], self.old)
        P(210, 300, "node", ["npm", "start"], self.old)
        P(211, 210, "sh", ["sh", "-c", "node server.js"], os.path.join(b, "bash"))
        P(212, 211, "node", ["node", "server.js"], self.new)
        P(220, 300, "node", ["node", "/srv/worker/index.js"],
          os.path.join(r, "fnm/node-versions/v24.14.0/installation/bin/node"))
        P(230, 300, "node", ["node", "/srv/fresh/index.js"], self.new)
        P(240, 300, "node", ["node", "/srv/stale/index.js"], self.old)
        P(250, 300, "python3", ["python3", "run.py"], os.path.join(b, "bash"))
        P(260, 300, "node", ["node", "/srv/clustered/index.js"], self.old)

        self.pm2_home = os.path.join(r, "pm2home")
        os.makedirs(self.pm2_home)
        open(os.path.join(self.pm2_home, "pm2.pid"), "w").write("300\n")
        self.jlist = render(os.path.join(FIX, "pm2-jlist.json"), os.path.join(r, "jlist.json"), r)
        dump = [dict(e["pm2_env"], pid=e["pid"]) for e in json.load(open(self.jlist))]
        self.dump = os.path.join(r, "dump.pm2")
        json.dump(dump, open(self.dump, "w"))
        self.crontab = render(os.path.join(FIX, "crontab.txt"), os.path.join(r, "crontab"), r)
        self.units = os.path.join(r, "units")
        for u in os.listdir(os.path.join(FIX, "units")):
            render(os.path.join(FIX, "units", u), os.path.join(self.units, u), r)

    def add_proc(self, pid, ppid, comm, argv, exe, mnt="mnt:[1]", maps=""):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(os.path.join(d, "ns"))
        open(os.path.join(d, "stat"), "w").write("%d (%s) S %d 1 1 0 -1\n" % (pid, comm, ppid))
        open(os.path.join(d, "status"), "w").write("Name:\t%s\nUid:\t0\t0\t0\t0\n" % comm[:15])
        open(os.path.join(d, "cmdline"), "wb").write(b"\0".join(a.encode() for a in argv) + b"\0")
        open(os.path.join(d, "maps"), "w").write(maps)
        os.symlink(exe, os.path.join(d, "exe"))
        os.symlink(mnt, os.path.join(d, "ns", "mnt"))

    def args(self, *extra):
        return ["--proc-root", self.proc, "--pm2-jlist-file", self.jlist, "--pm2-home", self.pm2_home,
                "--pm2-dump-file", self.dump, "--crontab-file", self.crontab,
                "--systemd-dir", self.units, "--container-cli", os.path.join(FIX, "fake-docker.sh"),
                "--no-installs"] + list(extra)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


real_readlink = os.readlink


def readlink_denying_108(path, *a, **k):
    if str(path).endswith("/108/exe"):
        raise PermissionError(13, "Permission denied")
    return real_readlink(path, *a, **k)


def run(argv):
    buf = io.StringIO()
    with mock.patch.object(nra.os, "readlink", side_effect=readlink_denying_108), \
            contextlib.redirect_stdout(buf):
        code = nra.main(argv)
    return code, buf.getvalue()


class ClassifyTest(unittest.TestCase):
    def test_lines(self):
        c = lambda v: nra.classify(v, FIXED)[0]  # noqa: E731
        self.assertEqual(c("v24.22.1"), "patched")
        self.assertEqual(c("24.22.2"), "patched")
        self.assertEqual(c("v24.22.0"), "vulnerable")
        self.assertEqual(c("v22.23.3"), "vulnerable")
        self.assertEqual(c("v22.23.4"), "patched")
        self.assertEqual(c("v26.12.0"), "vulnerable")
        self.assertEqual(c("v26.12.1"), "patched")

    def test_end_of_life_lines_have_no_fix(self):
        for v in ("v25.9.0", "v23.11.1", "v20.20.2", "v18.20.8", "v16.20.2"):
            self.assertEqual(nra.classify(v, FIXED)[0], "vulnerable", v)

    def test_unknown_is_never_patched(self):
        for v in (None, "", "garbage", "v27.0.0", "v26.13.0-rc.1", "v24.22.1-nightly20261020"):
            self.assertEqual(nra.classify(v, FIXED)[0], "unknown", v)

    def test_parse_fixed(self):
        self.assertEqual(nra.parse_fixed("24=24.22.1")[24], (24, 22, 1))
        for bad in ("", "24", "x=1.2.3", "24=24.22.1-rc.1"):
            with self.assertRaises(ValueError):
                nra.parse_fixed(bad)


class PathTest(unittest.TestCase):
    def test_pinned_versions(self):
        cases = {
            "/home/u/.nvm/versions/node/v24.14.0/bin/node": "v24.14.0",
            "/home/u/.local/share/fnm/node-versions/v24.14.0/installation/bin": "v24.14.0",
            "/usr/local/n/versions/node/22.1.0/bin/node": "v22.1.0",
            "/home/u/.volta/tools/image/node/24.1.0/bin/node": "v24.1.0",
            "/home/u/.asdf/installs/nodejs/20.11.0/bin/npm": "v20.11.0",
            "/opt/node-v24.14.0-linux-x64/bin/node": "v24.14.0",
            "/usr/bin/node": None,
            "/home/u/.local/share/fnm/aliases/default/bin/node": None,
        }
        for path, want in cases.items():
            self.assertEqual(nra.pinned_version(path), want, path)

    def test_find_node_paths_skips_comments_and_urls(self):
        text = open(os.path.join(FIX, "crontab.txt")).read().replace("{ROOT}", "/r")
        found = list(nra.find_node_paths(text))
        lines = [n for n, _ in found]
        paths = [p for _, p in found]
        self.assertNotIn(3, lines)  # commented job
        self.assertNotIn(7, lines)  # URL
        self.assertIn("/r/nvm/versions/node/v24.14.0/bin", paths)  # PATH= entry
        self.assertIn("/r/nvm/versions/node/v24.14.0/bin/npx", paths)
        self.assertEqual(lines.count(8), 1)  # same path twice on one line


class HostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = FakeHost()
        cls.code, out = run(cls.host.args("--json"))
        cls.rep = json.loads(out)
        cls.procs = {p["pid"]: p for p in cls.rep["processes"]}

    @classmethod
    def tearDownClass(cls):
        cls.host.cleanup()

    def test_process_statuses(self):
        want = {100: "vulnerable", 101: "patched", 102: "vulnerable", 103: "patched",
                105: "vulnerable", 106: "unknown", 107: "unknown", 108: "unknown",
                109: "unknown", 110: "vulnerable", 111: "unknown", 112: "vulnerable",
                113: "patched", 114: "unknown", 300: "vulnerable",
                200: "vulnerable", 212: "patched", 240: "vulnerable"}
        for pid, status in want.items():
            self.assertEqual(self.procs[pid]["status"], status, pid)
        self.assertNotIn(104, self.procs)  # bash is not Node
        self.assertNotIn(1, self.procs)

    def test_deleted_binary_is_judged_by_the_running_file(self):
        p = self.procs[102]
        self.assertTrue(p["deleted"])
        self.assertEqual(p["version"], "v24.14.0")
        self.assertTrue(any("replaced on disk" in n for n in p["notes"]))

    def test_container_binary_is_read_not_executed(self):
        p = self.procs[103]
        self.assertTrue(p["container"])
        self.assertEqual(p["method"], "embedded")

    def test_distro_and_system_brotli_builds_are_unknown(self):
        self.assertIn("distribution build", self.procs[107]["reason"])
        self.assertIn("libbrotlidec.so", self.procs[109]["reason"])
        self.assertTrue(any("libbrotlidec" in n for n in self.procs[109]["notes"]))

    def test_found_binaries_are_never_executed_by_default(self):
        # 110, 111, 113 and 114 are scripts that would create the marker.
        self.assertFalse(os.path.exists(self.host.marker))
        self.assertEqual((self.procs[110]["version"], self.procs[110]["method"]),
                         ("v24.14.0", "embedded"))
        self.assertIsNone(self.procs[111]["version"])
        self.assertIn("version not found", self.procs[111]["reason"])

    def test_version_from_install_header(self):
        self.assertEqual((self.procs[113]["version"], self.procs[113]["method"]),
                         ("v24.22.1", "node_version.h"))

    def test_directory_name_is_not_proof(self):
        self.assertIsNone(self.procs[114]["version"])
        self.assertIn("directory name says v26.12.1", self.procs[114]["reason"])

    def test_terminal_escapes_are_neutralized(self):
        for out in (run(self.host.args())[1], run(self.host.args("--json"))[1],
                    run(self.host.args("--redact"))[1]):
            for bad in ("\x1b", "\x07", "\x9b"):
                self.assertNotIn(bad, out)
            self.assertIn("\\x1b]0;pwned\\x07evil.js", out.replace("\\\\", "\\"))
        c = [x["name"] for x in self.rep["containers"]["items"]]
        self.assertIn("evil\\x1b[2Jname", c)

    def test_unreadable_process_is_unknown(self):
        self.assertIn("run as root", self.procs[108]["reason"])
        self.assertNotIn("abc", self.procs[108]["cmd"])

    def test_npm_child_resolves_node_from_path(self):
        self.assertEqual(self.procs[210]["version"], "v24.14.0")
        self.assertEqual(self.procs[212]["version"], "v24.22.1")
        self.assertEqual(self.procs[212]["parents"][:2], ["sh(211)", "node(210)"])

    def pm2(self, kind):
        sec = next(s for s in self.rep["pm2"] if s["kind"] == kind)
        return sec, {e["name"]: e for e in sec["entries"]}

    def test_pm2_live_entries(self):
        sec, e = self.pm2("live list")
        self.assertEqual(sec["daemon"]["status"], "vulnerable")
        self.assertEqual(e["api"]["status"], "vulnerable")
        interp = next(f for f in e["api"]["findings"] if f["what"] == "interpreter")
        self.assertTrue(interp["pinned"])
        self.assertEqual(interp["version"], "v24.14.0")
        script = next(f for f in e["web"]["findings"] if f["what"] == "script")
        self.assertEqual((script["status"], script["version"]), ("vulnerable", "v24.14.0"))
        self.assertEqual(e["web"]["status"], "vulnerable")
        self.assertEqual(sorted(p["pid"] for p in e["web"]["running"]), [210, 212])
        worker = next(f for f in e["worker"]["findings"] if f["what"] == "PATH node")
        self.assertEqual((worker["version"], worker["pinned"]), ("v24.14.0", True))
        self.assertEqual(e["fresh"]["status"], "patched")
        self.assertEqual(e["py-job"]["status"], "none")
        self.assertEqual(e["no-node"]["status"], "unknown")

    def test_running_process_beats_config(self):
        # The entry's saved PATH already points at the fixed Node, but the
        # process was never restarted. A config-only check calls it patched.
        _, live = self.pm2("live list")
        self.assertTrue(all(f["status"] == "patched" for f in live["stale-config"]["findings"]))
        self.assertEqual(live["stale-config"]["status"], "vulnerable")
        _, saved = self.pm2("saved list")
        self.assertEqual(saved["stale-config"]["status"], "patched")

    def test_cluster_mode_follows_the_daemon(self):
        # Cluster workers are forked by the daemon, so the fixed PATH in the
        # entry does not matter: only moving the daemon (pm2 update) does.
        _, live = self.pm2("live list")
        f = live["clustered"]["findings"]
        self.assertEqual([x["what"] for x in f], ["daemon node"])
        self.assertEqual((f[0]["version"], live["clustered"]["status"]), ("v24.14.0", "vulnerable"))
        _, saved = self.pm2("saved list")
        self.assertEqual(saved["clustered"]["status"], "none")
        self.assertIn("starts the pm2 daemon", saved["clustered"]["findings"][0]["reason"])

    def test_saved_list_is_checked(self):
        _, saved = self.pm2("saved list")
        self.assertEqual(saved["api"]["status"], "vulnerable")
        self.assertEqual(saved["worker"]["status"], "vulnerable")
        self.assertEqual(saved["api"]["running"], [])

    def test_crontab(self):
        by_line = {}
        for r in self.rep["cron"]:
            by_line.setdefault(int(r["where"].rsplit(":", 1)[1]), []).append(r)
        self.assertEqual(by_line[2][0]["status"], "vulnerable")  # PATH= entry
        self.assertEqual(by_line[4][0]["status"], "patched")
        self.assertTrue(by_line[4][0]["pinned"])
        self.assertEqual(by_line[5][0]["status"], "vulnerable")  # npx under the old install
        self.assertEqual(by_line[6][0]["status"], "missing")
        self.assertIn("v20.11.0 (vulnerable)", by_line[6][0]["reason"])
        self.assertNotIn(3, by_line)
        self.assertNotIn(7, by_line)

    def test_systemd(self):
        rows = [(os.path.basename(r["where"]), r["status"], r["pinned"]) for r in self.rep["systemd"]]
        pm2_rows = [r for r in rows if r[0].startswith("pm2-deploy.service")]
        self.assertEqual(len(pm2_rows), 4)  # PATH, ExecStart, ExecReload, ExecStop
        self.assertTrue(all(s == "vulnerable" and p for _, s, p in pm2_rows))
        api = [r for r in rows if r[0].startswith("api.service")]
        self.assertEqual(api, [("api.service:8", "patched", False)])

    def test_containers(self):
        c = {x["name"]: x for x in self.rep["containers"]["items"]}
        self.assertEqual(c["shop-api"]["status"], "vulnerable")
        self.assertEqual(c["new-api"]["status"], "patched")
        self.assertEqual(c["distroless-app"]["status"], "unknown")
        self.assertNotIn("cache", c)

    def test_exit_code_and_no_secrets(self):
        self.assertEqual(self.code, 1)
        code, text = run(self.host.args())
        self.assertEqual(code, 1)
        for out in (text, json.dumps(self.rep)):
            self.assertNotIn("do-not-print-me", out)
            self.assertNotIn("secret-value", out)
            self.assertNotIn("--token=abc", out)

    def test_redaction(self):
        _, text = run(self.host.args("--redact"))
        self.assertNotIn("stale-config", text)
        self.assertIn("app-", text)
        _, js = run(self.host.args("--redact", "--json"))
        self.assertNotIn("stale-config", js)


class ExitCodeTest(unittest.TestCase):
    def setUp(self):
        self.host = FakeHost()

    def tearDown(self):
        self.host.cleanup()

    def only(self, *pids):
        for name in os.listdir(self.host.proc):
            if name.isdigit() and int(name) not in pids:
                shutil.rmtree(os.path.join(self.host.proc, name))
        return run(["--proc-root", self.host.proc, "--no-pm2", "--no-cron", "--no-systemd",
                    "--no-containers", "--no-installs"])

    def test_unknown_only_exits_2(self):
        code, out = self.only(1, 106)
        self.assertEqual(code, 2)
        self.assertIn("UNKNOWN", out)

    def test_patched_exits_0(self):
        code, out = self.only(1, 101, 103)
        self.assertEqual(code, 0)
        self.assertIn("nothing vulnerable found", out)

    def test_no_node_exits_0_and_says_so(self):
        code, out = self.only(1, 104)
        self.assertEqual(code, 0)
        self.assertIn("no Node found", out)


class ExecVersionTest(unittest.TestCase):
    """--exec-version is opt-in and refuses anything someone else could swap."""

    def setUp(self):
        # Under the repo, not /tmp: /tmp is world-writable, so the directory
        # check refuses everything below it, which is the point.
        self.d = tempfile.mkdtemp(prefix="nra-exec-", dir=HERE)
        os.chmod(self.d, 0o755)
        self.addCleanup(shutil.rmtree, self.d)
        probe = os.path.join(self.d, "probe")
        script_binary(probe, "v26.12.1")
        version, why = nra.exec_version_hardened(probe)
        if version is None:
            self.skipTest("checkout path is not trusted here: %s" % why)

    def test_trusted_binary_runs_through_its_fd(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v26.12.1")
        self.assertEqual(nra.exec_version_hardened(p), ("v26.12.1", None))

    def test_group_writable_binary_is_refused(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v26.12.1", mode=0o775, marker=os.path.join(self.d, "ran"))
        os.chmod(p, 0o775)
        version, why = nra.exec_version_hardened(p)
        self.assertIsNone(version)
        self.assertIn("writable by group/others", why)
        self.assertFalse(os.path.exists(os.path.join(self.d, "ran")))

    def test_writable_directory_is_refused(self):
        sub = os.path.join(self.d, "open")
        p = os.path.join(sub, "node")
        script_binary(p, "v26.12.1")
        os.chmod(sub, 0o777)
        version, why = nra.exec_version_hardened(p)
        self.assertIsNone(version)
        self.assertIn("directory %s" % sub, why)

    def test_root_refuses_binaries_it_does_not_own(self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root owner")
        p = os.path.join(self.d, "node")
        script_binary(p, "v26.12.1", marker=os.path.join(self.d, "ran"))
        with mock.patch.object(nra.os, "geteuid", return_value=0):
            version, why = nra.exec_version_hardened(p)
        self.assertIsNone(version)
        self.assertIn("not owned by root", why)
        self.assertFalse(os.path.exists(os.path.join(self.d, "ran")))

    def test_swapped_file_is_refused(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v26.12.1")
        version, why = nra.exec_version_hardened(p, expect=(0, 0))
        self.assertIsNone(version)
        self.assertIn("changed", why)

    def test_disagreement_with_the_embedded_version_is_unknown(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v24.22.1", embedded="24.14.0")
        info = nra.BinaryInspector(exec_version=True).inspect(p, install_path=p, exec_path=p)
        self.assertIsNone(info["version"])
        self.assertIn("--version says v24.22.1", info["error"])
        self.assertEqual(nra.judge_binary(info, FIXED)[0], "unknown")

    def test_off_by_default(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v26.12.1", marker=os.path.join(self.d, "ran"))
        info = nra.BinaryInspector().inspect(p, install_path=p, exec_path=p)
        self.assertIsNone(info["version"])
        self.assertFalse(os.path.exists(os.path.join(self.d, "ran")))


class FifoTest(unittest.TestCase):
    """A FIFO planted where a file is expected must not stall the audit."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="nra-fifo-")
        self.addCleanup(shutil.rmtree, self.d)

        def blocked(*_):
            raise AssertionError("the audit blocked on a FIFO")

        old = signal.signal(signal.SIGALRM, blocked)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        signal.alarm(20)
        self.addCleanup(signal.alarm, 0)

    def install(self, header):
        """bin/node without an embedded version, and node_version.h as given."""
        root = os.path.join(self.d, "node-v24.22.1")
        node = os.path.join(root, "bin", "node")
        script_binary(node, "v24.22.1")
        h = os.path.join(root, "include", "node", "node_version.h")
        os.makedirs(os.path.dirname(h))
        if header == "fifo":
            os.mkfifo(h)
        else:
            open(h, "w").write("#define NODE_MAJOR_VERSION 24\n#define NODE_MINOR_VERSION 22\n"
                               "#define NODE_PATCH_VERSION 1\n")
            os.chmod(h, header)
        return node

    def test_fifo_header_is_refused(self):
        node = self.install("fifo")
        info = nra.BinaryInspector().inspect(node, install_path=node)
        self.assertIsNone(info["version"])
        self.assertIn("not a regular file", info["header_refused"])
        self.assertEqual(nra.judge_binary(info, FIXED)[0], "unknown")

    def test_header_writable_by_others_is_refused(self):
        node = self.install(0o666)
        info = nra.BinaryInspector().inspect(node, install_path=node)
        self.assertIsNone(info["version"])
        self.assertIn("writable by others", info["header_refused"])

    def test_good_header_is_used(self):
        node = self.install(0o644)
        info = nra.BinaryInspector().inspect(node, install_path=node)
        self.assertEqual((info["version"], info["method"]), ("v24.22.1", "node_version.h"))

    def test_fifos_in_config_paths_do_not_block(self):
        proc = os.path.join(self.d, "proc")
        os.makedirs(proc)
        fifo_node = os.path.join(self.d, "fifo/versions/node/v24.1.0/bin/node")
        os.makedirs(os.path.dirname(fifo_node))
        os.mkfifo(fifo_node)
        crontab = os.path.join(self.d, "crontab")
        open(crontab, "w").write("* * * * * %s /srv/job.js\n" % fifo_node)
        cron_fifo = os.path.join(self.d, "crontab-fifo")
        os.mkfifo(cron_fifo)
        scan = os.path.join(self.d, "scripts")
        os.makedirs(scan)
        os.mkfifo(os.path.join(scan, "job.sh"))
        units = os.path.join(self.d, "units")
        os.makedirs(units)
        os.mkfifo(os.path.join(units, "app.service"))
        pm2 = os.path.join(self.d, "pm2")
        os.makedirs(pm2)
        os.mkfifo(os.path.join(pm2, "pm2.pid"))
        os.mkfifo(os.path.join(pm2, "dump.pm2"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, out = run(["--proc-root", proc, "--crontab-file", crontab, "--crontab-file", cron_fifo,
                             "--scan-path", scan, "--systemd-dir", units, "--pm2-home", pm2,
                             "--no-containers", "--no-installs", "--json"])
        rep = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual(rep["cron"][0]["status"], "unknown")
        self.assertIn("not a regular file", rep["cron"][0]["reason"])
        self.assertIn("cannot read", err.getvalue())
        self.assertEqual(rep["extra"], [])
        self.assertEqual(rep["systemd"], [])


class CleanTest(unittest.TestCase):
    def test_control_characters_are_escaped(self):
        self.assertEqual(nra.clean("a\x1b]0;t\x07b\x7f\x9b\n\tc \u00e9"),
                         "a\\x1b]0;t\\x07b\\x7f\\x9b\\x0a\\x09c \u00e9")
        tree = nra.clean_tree({"k\x1b": ["x\x1b", ("y\x07",)], 24: (24, 22, 1)})
        self.assertEqual(tree, {"k\\x1b": ["x\\x1b", ("y\\x07",)], 24: (24, 22, 1)})


class InstallsTest(unittest.TestCase):
    def test_version_managers_and_default_alias(self):
        home = tempfile.mkdtemp()
        try:
            node_binary(os.path.join(home, ".nvm/versions/node/v24.14.0/bin/node"), "24.14.0")
            node_binary(os.path.join(home, ".nvm/versions/node/v24.22.1/bin/node"), "24.22.1")
            os.makedirs(os.path.join(home, ".nvm/alias"))
            open(os.path.join(home, ".nvm/alias/default"), "w").write("v24.14.0\n")
            fnm = os.path.join(home, ".local/share/fnm")
            node_binary(os.path.join(fnm, "node-versions/v22.23.4/installation/bin/node"), "22.23.4")
            os.makedirs(os.path.join(fnm, "aliases"))
            os.symlink(os.path.join(fnm, "node-versions/v22.23.4/installation"),
                       os.path.join(fnm, "aliases/default"))
            with mock.patch.dict(os.environ, {"NVM_DIR": "", "FNM_DIR": ""}):
                managers, _ = nra.installed_versions([home], FIXED)
            m = {x["manager"]: x for x in managers}
            self.assertEqual((m["nvm"]["default"], m["nvm"]["default_status"]), ("v24.14.0", "vulnerable"))
            self.assertEqual([v["status"] for v in m["nvm"]["versions"]], ["vulnerable", "patched"])
            self.assertEqual((m["fnm"]["default"], m["fnm"]["default_status"]), ("v22.23.4", "patched"))
        finally:
            shutil.rmtree(home)


if __name__ == "__main__":
    unittest.main()
