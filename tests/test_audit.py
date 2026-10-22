"""Tests for node_runtime_audit.py. Run: python3 -m unittest discover -s tests -v

Each test builds a fake host: Node binaries that carry their version the way
official builds do (an ELF file with the embedded headers URL), a fake /proc
tree, and pm2, crontab, systemd and docker fixtures. The cases are the ones a
config-only or version-only check gets wrong, and the ones where the script
itself could be fooled or stalled by what it finds.
"""

import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import node_runtime_audit as nra  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
FIXED = nra.parse_fixed(nra.FIXED_DEFAULT)
ME = os.geteuid()


def node_binary(path, version, extra=b"", mode=0o755):
    """A fake ELF file with the version string official builds embed."""
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


def add_proc(proc, pid, ppid, comm, argv, exe, mnt="mnt:[1]", maps="", uid=ME):
    d = os.path.join(proc, str(pid))
    os.makedirs(os.path.join(d, "ns"))
    open(os.path.join(d, "stat"), "w").write("%d (%s) S %d 1 1 0 -1\n" % (pid, comm, ppid))
    open(os.path.join(d, "status"), "w").write("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n" % (
        comm[:15], uid, uid, uid, uid))
    open(os.path.join(d, "cmdline"), "wb").write(b"\0".join(a.encode() for a in argv) + b"\0")
    open(os.path.join(d, "maps"), "w").write(maps)
    if exe:
        os.symlink(exe, os.path.join(d, "exe"))
    os.symlink(mnt, os.path.join(d, "ns", "mnt"))


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
        # Shell wrappers: they would leave the marker if anything ran them,
        # and one mentions a version that must not be believed.
        script_binary(os.path.join(b, "wrapper/node"), "v24.22.1", embedded="24.22.1",
                      marker=self.marker)
        script_binary(os.path.join(b, "execonly/node"), "v26.12.1", marker=self.marker)
        script_binary(os.path.join(r, "opt/node-v26.12.1-linux-arm64/bin/node"), "v26.12.1",
                      marker=self.marker)
        node_binary(os.path.join(b, "bash"), None)
        node_binary(os.path.join(b, "systemd"), None)

        self.pm2_home = os.path.join(r, "pm2home")
        os.makedirs(self.pm2_home)
        self.proc = os.path.join(r, "proc")
        os.makedirs(os.path.join(self.proc, "self/ns"))
        os.symlink("mnt:[1]", os.path.join(self.proc, "self/ns/mnt"))
        P = lambda *a, **k: add_proc(self.proc, *a, **k)  # noqa: E731
        P(1, 0, "systemd", ["/sbin/init"], os.path.join(b, "systemd"), uid=0)
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
        P(110, 1, "node", ["node", "wrapper.js"], os.path.join(b, "wrapper/node"))
        P(111, 1, "node", ["node", "execonly.js"], os.path.join(b, "execonly/node"))
        P(112, 1, "node", ["node", "\x1b]0;pwned\x07evil.js", "\x1b[2J"], self.old)
        P(114, 1, "node", ["node", "named.js"],
          os.path.join(r, "opt/node-v26.12.1-linux-arm64/bin/node"))
        # pm2: the daemon is found in /proc by its title and PM2_HOME
        P(300, 1, "PM2 v6.0.14: Go", ["PM2 v6.0.14: God Daemon (%s)" % self.pm2_home], self.old)
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

        self.jlist = render(os.path.join(FIX, "pm2-jlist.json"), os.path.join(r, "jlist.json"), r)
        self.crontab = render(os.path.join(FIX, "crontab.txt"), os.path.join(r, "crontab"), r)
        self.units = os.path.join(r, "units")
        for u in os.listdir(os.path.join(FIX, "units")):
            render(os.path.join(FIX, "units", u), os.path.join(self.units, u), r)

    def args(self, *extra):
        return ["--proc-root", self.proc, "--pm2-jlist-file", self.jlist, "--pm2-home", self.pm2_home,
                "--crontab-file", self.crontab, "--systemd-dir", self.units,
                "--container-cli", os.path.join(FIX, "fake-docker.sh"), "--no-installs"] + list(extra)

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
        for bad in ("", "24", "x=1.2.3", "24=24.22.1-rc.1", "24=22.23.4"):
            with self.assertRaises(ValueError):
                nra.parse_fixed(bad)

    def test_a_path_name_never_makes_patched(self):
        self.assertEqual(nra.hint_status("v24.14.0", FIXED)[0], "vulnerable")
        self.assertEqual(nra.hint_status("v24.22.1", FIXED)[0], "unknown")
        self.assertEqual(nra.hint_status(None, FIXED)[0], "unknown")


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
                109: "unknown", 110: "unknown", 111: "unknown", 112: "vulnerable",
                114: "unknown", 300: "vulnerable", 200: "vulnerable", 212: "patched",
                240: "vulnerable"}
        for pid, status in want.items():
            self.assertEqual(self.procs[pid]["status"], status, pid)
        self.assertNotIn(104, self.procs)  # bash is not Node
        self.assertNotIn(1, self.procs)

    def test_found_binaries_are_never_executed(self):
        # 110, 111 and 114 are scripts that would create the marker.
        self.assertFalse(os.path.exists(self.host.marker))
        self.assertIsNone(self.procs[111]["version"])

    def test_a_wrapper_mentioning_a_version_is_not_believed(self):
        self.assertIsNone(self.procs[110]["version"])
        self.assertIn("not an ELF binary", self.procs[110]["reason"])

    def test_directory_name_is_not_proof(self):
        self.assertIsNone(self.procs[114]["version"])
        self.assertIn("from path: v26.12.1 (a hint, not proof)", self.procs[114]["reason"])

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

    def test_unreadable_process_is_unknown(self):
        self.assertIn("as its owner", self.procs[108]["reason"])
        self.assertNotIn("abc", self.procs[108]["cmd"])

    def test_npm_child_resolves_node_from_path(self):
        self.assertEqual(self.procs[210]["version"], "v24.14.0")
        self.assertEqual(self.procs[212]["version"], "v24.22.1")
        self.assertEqual(self.procs[212]["parents"][:2], ["sh(211)", "node(210)"])

    def test_terminal_escapes_are_neutralized(self):
        for out in (run(self.host.args())[1], run(self.host.args("--json"))[1],
                    run(self.host.args("--redact"))[1]):
            for bad in ("\x1b", "\x07", "\x9b"):
                self.assertNotIn(bad, out)
            self.assertIn("\\x1b]0;pwned\\x07evil.js", out.replace("\\\\", "\\"))
        c = [x["name"] for x in self.rep["containers"]["items"]]
        self.assertIn("evil\\x1b[2Jname", c)

    def pm2(self):
        sec = self.rep["pm2"][0]
        return sec, {e["name"]: e for e in sec["entries"]}

    def test_pm2_live_entries(self):
        sec, e = self.pm2()
        self.assertEqual(sec["daemon"]["pid"], 300)
        self.assertEqual(sec["daemon"]["status"], "vulnerable")
        self.assertEqual(e["api"]["status"], "vulnerable")
        interp = next(f for f in e["api"]["findings"] if f["what"] == "interpreter")
        self.assertTrue(interp["pinned"])
        self.assertEqual(interp["version"], "v24.14.0")
        self.assertIn("same file as running pid", interp["reason"])
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
        _, live = self.pm2()
        self.assertTrue(all(f["status"] == "patched" for f in live["stale-config"]["findings"]))
        self.assertEqual(live["stale-config"]["status"], "vulnerable")

    def test_cluster_mode_follows_the_daemon(self):
        # Cluster workers are forked by the daemon, so the fixed PATH in the
        # entry does not matter: only moving the daemon (pm2 update) does.
        _, live = self.pm2()
        f = live["clustered"]["findings"]
        self.assertEqual([x["what"] for x in f], ["daemon node", "PATH node"])
        self.assertEqual((f[0]["version"], live["clustered"]["status"]), ("v24.14.0", "vulnerable"))

    def test_crontab(self):
        by_line = {}
        for r in self.rep["cron"]:
            by_line.setdefault(int(r["where"].rsplit(":", 1)[1]), []).append(r)
        self.assertEqual(by_line[2][0]["status"], "vulnerable")  # PATH= entry
        self.assertEqual(by_line[4][0]["status"], "patched")  # same file as a running process
        self.assertTrue(by_line[4][0]["pinned"])
        self.assertEqual(by_line[5][0]["status"], "vulnerable")  # npx under the old install
        self.assertEqual(by_line[6][0]["status"], "missing")
        self.assertIn("v20.11.0 (vulnerable)", by_line[6][0]["reason"])
        self.assertNotIn(3, by_line)
        self.assertNotIn(7, by_line)
        # npx next to a fixed node still runs on whatever node PATH gives it
        self.assertEqual(by_line[9][0]["status"], "unknown")
        self.assertIn("first `node` on the PATH", by_line[9][0]["reason"])

    def test_systemd(self):
        rows = [(os.path.basename(r["where"]), r["status"], r["pinned"]) for r in self.rep["systemd"]]
        pm2_rows = [r for r in rows if r[0].startswith("pm2-deploy.service")]
        self.assertEqual(len(pm2_rows), 4)  # PATH, ExecStart, ExecReload, ExecStop
        self.assertTrue(all(s == "vulnerable" and p for _, s, p in pm2_rows))
        api = {r["where"].rsplit("/", 1)[1]: r for r in self.rep["systemd"]
               if r["where"].rsplit("/", 1)[1].startswith("api.service")}
        # ExecStart names a node no process runs and whose path has no version
        self.assertEqual(api["api.service:9"]["status"], "unknown")
        self.assertIn("binaries outside /proc are not read", api["api.service:9"]["reason"])
        # EnvironmentFile= is listed, never read
        self.assertEqual(api["api.service:7"]["status"], "unknown")
        self.assertIn("EnvironmentFile not read", api["api.service:7"]["reason"])

    def test_containers(self):
        c = {x["name"]: x for x in self.rep["containers"]["items"]}
        self.assertEqual(c["shop-api"]["status"], "vulnerable")
        self.assertEqual(c["new-api"]["status"], "patched")
        self.assertEqual(c["distroless-app"]["status"], "unknown")
        self.assertNotIn("cache", c)
        self.assertEqual(c["paused-app"]["status"], "unknown")
        self.assertIn("exec exit 1", c["paused-app"]["reason"])

    def test_no_container_exec(self):
        _, out = run(self.host.args("--json", "--no-container-exec"))
        c = {x["name"]: x for x in json.loads(out)["containers"]["items"]}
        self.assertEqual(c["shop-api"]["status"], "unknown")
        self.assertIn("NODE_VERSION=22.22.0 (a hint, not proof)", c["shop-api"]["reason"])

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


class UnlinkedProcessTest(unittest.TestCase):
    """A real process whose binary was deleted after it started: the script
    must read the running file through /proc/<pid>/exe (zero links)."""

    def test_deleted_running_binary(self):
        src = shutil.which("sleep")
        if not src or not os.path.isdir("/proc/self"):
            self.skipTest("needs /proc and a sleep binary")
        d = tempfile.mkdtemp(prefix="nra-unlinked-", dir=HERE)
        self.addCleanup(shutil.rmtree, d, True)
        node = os.path.join(d, "node")
        shutil.copyfile(os.path.realpath(src), node)
        with open(node, "ab") as f:  # trailing bytes do not stop an ELF from running
            f.write(b"\0node-v24.14.0-headers.tar.gz\0")
        os.chmod(node, 0o755)
        try:
            proc = subprocess.Popen([node, "30"])
        except OSError as e:
            self.skipTest("cannot run a copied binary here: %s" % e)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        time.sleep(0.3)
        os.unlink(node)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nra.main(["--no-pm2", "--no-cron", "--no-systemd", "--no-containers", "--no-installs",
                      "--json"])
        p = next(x for x in json.loads(buf.getvalue())["processes"] if x["pid"] == proc.pid)
        self.assertTrue(p["deleted"])
        self.assertEqual((p["version"], p["status"]), ("v24.14.0", "vulnerable"))


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
        self.assertIn("writable by group or others", why)
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
        if ME == 0:
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

    def test_config_path_with_exec_version(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v24.22.1")
        on = nra.judge_path(p, nra.Context(FIXED, exec_version=True))
        self.assertEqual((on["version"], on["status"]), ("v24.22.1", "patched"))
        off = nra.judge_path(p, nra.Context(FIXED))
        self.assertEqual(off["status"], "unknown")

    def test_off_by_default(self):
        p = os.path.join(self.d, "node")
        script_binary(p, "v26.12.1", marker=os.path.join(self.d, "ran"))
        info = nra.BinaryInspector().inspect(p, exec_path=p)
        self.assertIsNone(info["version"])
        nra.judge_path(p, nra.Context(FIXED))
        self.assertFalse(os.path.exists(os.path.join(self.d, "ran")))


class FileSafetyTest(unittest.TestCase):
    """FIFOs, devices, hard links and symlinks where a file is expected."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="nra-fifo-")
        self.addCleanup(shutil.rmtree, self.d)

        def blocked(*_):
            raise AssertionError("the audit blocked on a FIFO")

        old = signal.signal(signal.SIGALRM, blocked)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        signal.alarm(20)
        self.addCleanup(signal.alarm, 0)

    def test_open_pinned_refuses_what_is_not_a_plain_file(self):
        fifo = os.path.join(self.d, "fifo")
        os.mkfifo(fifo)
        real = os.path.join(self.d, "real")
        open(real, "w").write("x")
        link = os.path.join(self.d, "hard")
        os.link(real, link)
        sym = os.path.join(self.d, "sym")
        os.symlink(real, sym)
        cases = [("/dev/zero", {}, "not a regular file"), (fifo, {}, "not a regular file"),
                 (link, {}, "has 2 hard links"), (sym, {"follow": False}, "is a symlink")]
        for path, kw, msg in cases:
            with self.assertRaises(OSError) as ctx:
                nra.open_pinned(path, **kw)
            self.assertIn(msg, str(ctx.exception), path)

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
        units = os.path.join(self.d, "units")
        os.makedirs(units)
        os.mkfifo(os.path.join(units, "app.service"))
        code, out = run(["--proc-root", proc, "--crontab-file", crontab, "--crontab-file", cron_fifo,
                         "--systemd-dir", units, "--no-pm2", "--no-containers", "--no-installs",
                         "--json"])
        rep = json.loads(out)
        self.assertEqual(code, 1)
        # The FIFO named as node is never opened; its path names an unfixed version.
        self.assertEqual(rep["cron"][0]["status"], "vulnerable")
        self.assertIn("from path: v24.1.0", rep["cron"][0]["reason"])
        # The crontab that is a FIFO is unknown, not silently clean.
        self.assertEqual(rep["cron"][1]["status"], "unknown")
        self.assertIn("cannot read: not a regular file", rep["cron"][1]["reason"])
        self.assertEqual(rep["systemd"], [])

    def test_hard_linked_unit_is_unknown(self):
        units = os.path.join(self.d, "units")
        os.makedirs(units)
        real = os.path.join(self.d, "elsewhere.service")
        open(real, "w").write("[Service]\nExecStart=/opt/node-v24.1.0/bin/node app.js\n")
        os.link(real, os.path.join(units, "app.service"))
        rows = nra.scan_text_sources(nra.systemd_sources([units]), nra.Context(FIXED))
        self.assertEqual(rows[0]["status"], "unknown")
        self.assertIn("has 2 hard links", rows[0]["reason"])

    def test_units_of_other_users_are_skipped(self):
        units = os.path.join(self.d, "units")
        os.makedirs(units)
        open(os.path.join(units, "app.service"), "w").write("ExecStart=/opt/node-v24.1.0/bin/node\n")
        self.assertEqual(len(nra.systemd_sources([units])), 1)
        if ME != 0:
            with mock.patch.object(nra.os, "geteuid", return_value=ME + 1):
                self.assertEqual(nra.systemd_sources([units]), [])


class Pm2AndPathTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="nra-pm2-")
        self.addCleanup(shutil.rmtree, self.d)

    def test_relative_and_empty_path_entries_use_the_app_cwd(self):
        node_binary(os.path.join(self.d, "app/bin/node"), "24.14.0")
        d, _ = nra.resolve_on_path("bin:/nonexistent", cwd=os.path.join(self.d, "app"))
        self.assertEqual(d, os.path.join(self.d, "app/bin"))
        d, notes = nra.resolve_on_path("bin", cwd=None)
        self.assertIsNone(d)
        self.assertIn("no cwd", notes[0])

    def test_nodejs_interpreter_is_looked_up_as_nodejs(self):
        node_binary(os.path.join(self.d, "a/node"), "24.22.1")
        node_binary(os.path.join(self.d, "b/nodejs"), "24.14.0")
        entry = {"name": "x", "pm2_env": {"exec_interpreter": "nodejs",
                                         "PATH": "%s/a:%s/b" % (self.d, self.d)}}
        e = nra.pm2_entry(entry, nra.Context(FIXED), {}, {})
        f = next(x for x in e["findings"] if x["what"] == "PATH node")
        self.assertEqual(f["path"], os.path.join(self.d, "b"))

    def test_malformed_entry_is_unknown(self):
        for bad in ("x", {"pm2_env": "x"}, 3):
            e = nra.pm2_entry(bad, nra.Context(FIXED), {}, {})
            self.assertEqual(e["status"], "unknown")

    def daemon_proc(self, title):
        proc = os.path.join(self.d, "proc")
        add_proc(proc, 77, 1, "PM2", [title], None)
        return proc

    def test_live_list_failures_are_unknown(self):
        home = os.path.join(self.d, "pm2")
        os.makedirs(home)
        proc = self.daemon_proc("PM2 v6.0.14: God Daemon (%s)" % home)
        cli = os.path.join(self.d, "pm2-cli")
        open(cli, "w").write("#!/bin/sh\ntouch %s/RAN\necho []\n" % self.d)
        os.chmod(cli, 0o777)
        code, out = run(["--proc-root", proc, "--pm2-home", home, "--pm2-bin", cli, "--no-cron",
                         "--no-systemd", "--no-containers", "--no-installs", "--json"])
        sec = json.loads(out)["pm2"][0]
        self.assertIn("writable by group or others (mode 777): not run", sec["error"])
        self.assertEqual((code, sec["error_status"]), (2, "unknown"))
        self.assertFalse(os.path.exists(os.path.join(self.d, "RAN")))

    def test_failing_pm2_jlist_is_unknown(self):
        home = os.path.join(self.d, "pm2")
        os.makedirs(home)
        proc = self.daemon_proc("PM2 v6.0.14: God Daemon (%s)" % home)
        cli = os.path.join(self.d, "pm2-cli")
        open(cli, "w").write("#!/bin/sh\necho '[]'\nexit 3\n")
        os.chmod(cli, 0o755)
        code, out = run(["--proc-root", proc, "--pm2-home", home, "--pm2-bin", cli, "--no-cron",
                         "--no-systemd", "--no-containers", "--no-installs", "--json"])
        sec = json.loads(out)["pm2"][0]
        self.assertIn("pm2 jlist exited 3", sec["error"])
        self.assertEqual(code, 2)

    def test_no_daemon_means_no_jlist(self):
        home = os.path.join(self.d, "pm2")
        os.makedirs(home)
        proc = self.daemon_proc("PM2 v6.0.14: God Daemon (/somewhere/else)")
        args = mock.Mock(pm2_jlist_file=None, pm2_bin="/bin/false")
        data, err = nra.pm2_live(home, args, proc, nra.proc_table(proc))
        self.assertIsNone(data)
        self.assertIn("no pm2 daemon running", err)

    def test_failed_container_listing_is_unknown(self):
        cli = os.path.join(self.d, "docker")
        open(cli, "w").write("#!/bin/sh\necho 'permission denied' >&2\nexit 1\n")
        os.chmod(cli, 0o755)
        proc = os.path.join(self.d, "proc")
        os.makedirs(proc)
        code, out = run(["--proc-root", proc, "--container-cli", cli, "--no-pm2", "--no-cron",
                         "--no-systemd", "--no-installs", "--json"])
        self.assertEqual(code, 2)
        self.assertIn("permission denied", json.loads(out)["containers"]["errors"][0])


class InstallsTest(unittest.TestCase):
    def test_installs_are_listed_from_names_and_never_read(self):
        home = tempfile.mkdtemp()
        try:
            node_binary(os.path.join(home, ".nvm/versions/node/v24.14.0/bin/node"), "24.14.0")
            new = os.path.join(home, ".nvm/versions/node/v24.22.1/bin/node")
            node_binary(new, "24.22.1")
            # An old binary in a directory named after a fixed version
            node_binary(os.path.join(home, ".nvm/versions/node/v26.12.1/bin/node"), "26.11.0")
            os.makedirs(os.path.join(home, ".nvm/alias"))
            open(os.path.join(home, ".nvm/alias/default"), "w").write("v24.14.0\n")
            fnm = os.path.join(home, ".local/share/fnm")
            node_binary(os.path.join(fnm, "node-versions/v22.23.4/installation/bin/node"), "22.23.4")
            os.makedirs(os.path.join(fnm, "aliases"))
            os.symlink(os.path.join(fnm, "node-versions/v22.23.4/installation"),
                       os.path.join(fnm, "aliases/default"))
            st = os.stat(new)
            running = {"pid": 9, "inode": [st.st_dev, st.st_ino], "version": "v24.22.1",
                       "status": "patched", "reason": "v24.22.1 >= v24.22.1"}
            with mock.patch.dict(os.environ, {"NVM_DIR": "", "FNM_DIR": ""}):
                managers, _ = nra.installed_versions([home], nra.Context(FIXED, [running]))
            m = {x["manager"]: x for x in managers}
            self.assertEqual([(v["version"], v["source"]) for v in m["nvm"]["versions"]],
                             [("v24.14.0", "from path"), ("v24.22.1", "running"),
                              ("v26.12.1", "from path")])
            self.assertNotEqual(m["nvm"]["versions"][2]["status"], "patched")
            self.assertIn("not read", m["nvm"]["default"]["source"])
            self.assertEqual((m["fnm"]["default"]["version"], m["fnm"]["default"]["source"]),
                             ("v22.23.4", "from path"))
        finally:
            shutil.rmtree(home)


class UnitAndRedactTest(unittest.TestCase):
    def test_environment_file_only_listed_for_units_that_run_node(self):
        d = tempfile.mkdtemp(prefix="nra-units-")
        self.addCleanup(shutil.rmtree, d)
        open(os.path.join(d, "vpn.service"), "w").write(
            "[Unit]\nDescription=VPN node agent\n[Service]\nEnvironmentFile=-/etc/default/vpn\n"
            "ExecStart=/usr/sbin/vpnd\n")
        open(os.path.join(d, "web.service"), "w").write(
            "[Service]\nEnvironmentFile=/etc/default/web\nExecStart=/usr/bin/node /srv/web/server.js\n")
        rows = nra.scan_text_sources(nra.systemd_sources([d]), nra.Context(FIXED))
        env = [r for r in rows if "EnvironmentFile" in r["reason"]]
        self.assertEqual([os.path.basename(r["where"]) for r in env], ["web.service:2"])

    def test_redact_hides_project_names_without_pm2_entries(self):
        red = nra.Redactor(True)
        out = red("node /home/bob/projects/shop/node_modules/.bin/next dev /home/bob/.pm2")
        self.assertEqual(out, "node /home/USER/projects/app-1/node_modules/.bin/next dev /home/USER/.pm2")


class CleanTest(unittest.TestCase):
    def test_control_characters_are_escaped(self):
        self.assertEqual(nra.clean("a\x1b]0;t\x07b\x7f\x9b\n\tc é"),
                         "a\\x1b]0;t\\x07b\\x7f\\x9b\\x0a\\x09c é")
        tree = nra.clean_tree({"k\x1b": ["x\x1b", ("y\x07",)], 24: (24, 22, 1)})
        self.assertEqual(tree, {"k\\x1b": ["x\\x1b", ("y\\x07",)], 24: (24, 22, 1)})


if __name__ == "__main__":
    unittest.main()
