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


def script_binary(path, prints, embedded=None, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    body = "#!/bin/sh\necho %s\n" % prints
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
        script_binary(os.path.join(b, "mismatch/node"), "v24.22.1", embedded="24.14.0")
        script_binary(os.path.join(b, "execonly/node"), "v26.12.1")
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
                109: "unknown", 110: "unknown", 111: "patched", 300: "vulnerable",
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

    def test_version_disagreement_is_unknown(self):
        self.assertIn("--version says v24.22.1", self.procs[110]["reason"])

    def test_exec_only_build(self):
        self.assertEqual(self.procs[111]["method"], "--version")
        self.assertEqual(self.procs[111]["version"], "v26.12.1")

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


class SafetyTest(unittest.TestCase):
    def test_group_writable_binary_is_not_executed(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "node")
            script_binary(p, "v24.22.1", embedded="24.14.0", mode=0o775)
            os.chmod(p, 0o775)
            self.assertFalse(nra.safe_to_exec(p))
            info = nra.BinaryInspector().inspect(p, p)
            self.assertEqual((info["version"], info["method"]), ("v24.14.0", "embedded"))
        finally:
            shutil.rmtree(d)

    def test_no_exec_flag(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "node")
            script_binary(p, "v26.12.1")
            info = nra.BinaryInspector(allow_exec=False).inspect(p, p)
            self.assertIsNone(info["version"])
            self.assertEqual(nra.judge_binary(info, FIXED)[0], "unknown")
        finally:
            shutil.rmtree(d)


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
