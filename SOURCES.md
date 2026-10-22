# Sources and fact sheet

Every fact used in the companion post, with where it comes from. Times are UTC.
Checked on 2026-10-22 unless noted.

## The release

| Fact | Source |
| --- | --- |
| Node.js released security updates for the 26.x, 24.x and 22.x lines on Wednesday, 21 October 2026: v22.23.4, v24.22.1 and v26.12.1. "The highest severity issue fixed in this release is HIGH." | [Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) |
| "It's important to note that End-of-Life versions are always affected when a security release occurs." | same advisory |
| Dependency updates in the release: c-ares (26, 24, 22), "ca-cert (eMudhra Intermediate CA Compromise)" (26, 24, 22), OpenSSL (24, 22), SQLite (22), Undici (26, 24, 22). | same advisory |
| GitHub releases v26.12.1, v24.22.1 and v22.23.4 were published at 10:38:29, 10:38:25 and 10:38:20 UTC on 21 October. | `gh api repos/nodejs/node/releases/tags/<tag>` (`published_at`) |
| `SHASUMS256.txt` and the linux-arm64 tarballs are dated 21-Oct-2026 10:32 (22.23.4), 10:34 (24.22.1) and 10:36 (26.12.1) in the dist listings. | https://nodejs.org/dist/v22.23.4/ , /v24.22.1/ , /v26.12.1/ |
| Small discrepancy: `https://nodejs.org/dist/index.json` dates v22.23.4 and v24.22.1 as 2026-10-20 and v26.12.1 as 2026-10-21; the changelogs and advisory say 2026-10-21. | index.json, changelogs |

### The vulnerabilities (from the advisory)

| CVE | Title in the advisory | Severity | Lines |
| --- | --- | --- | --- |
| CVE-2026-111497 | Node.js Brotli decoder out-of-bounds write permits remote code execution | high | 26, 24, 22 |
| CVE-2026-105483 | TLS certificate hostname bypass when the IP is written fullwidth digits | high | 26, 24 |
| CVE-2026-106069 | TLS certificate hostname bypass when the host loosely resolves to an IP address | high | 26, 24, 22 |
| CVE-2026-105482 | dns.resolve truncates names containing NUL char | high | 26, 24, 22 |
| CVE-2026-105481 | Keep-alive socket process a response that was written before the request was sent | medium | 26, 24, 22 |
| CVE-2026-106072 | Improper certificate validation for non-canonical IPv4 hostnames allows DNS SANs to authenticate IP endpoints | medium | 26, 24, 22 |
| CVE-2026-106074 | crypto.randomUUID() and randomInt() entropy caches are saved into user-land startup snapshots and SEAs, so every process repeats the same values | medium | 26, 24, 22 |
| CVE-2026-106070 | Node.js ZipFile returns attacker-controlled prefix bytes after failed ZIP header validation | low | 26 |
| CVE-2026-106071 | Permission Model filesystem over-grant via wildcard radix lookup | low | 26 |
| CVE-2026-106073 | Permission Model bypass with fs.realpathSync | low | 26, 24, 22 |

The advisory body for CVE-2026-111497 reads: "A flaw in Node.js can cause Node.js Brotli decoder out-of-bounds write permits remote code execution." It does not say whether the bug has been exploited, and it gives no technical detail. Neither does this repo.

### The changelogs

From `doc/changelogs/CHANGELOG_V22.md`, `CHANGELOG_V24.md` and `CHANGELOG_V26.md` in [nodejs/node](https://github.com/nodejs/node):

- All three list "(CVE-2026-111497) deps: brotli: cherry-pick 0ed4268a4401abcb44720963" and "(CVE-2026-111497) src: expose `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`".
- All three list "crypto: update root certificates to NSS 3.131.1" and "tls: reject chains containing blocked public keys".
- 24.22.1 and 26.12.1 list "(CVE-2026-105483) tls: fix ip normalization regression". 22.23.4 does not, which matches the advisory (26 and 24 only).
- All three list "(CVE-2026-106069) tls: reject non-canonical IP addresses". Only the 26.12.1 entry also names CVE-2026-106072 on that line, although the advisory says CVE-2026-106072 affects 22 and 24 too.
- "(CVE-2026-105482) dns: validate resolve inputs for null bytes" in all three.
- Bundled undici: 6.29.1 (22.23.4), 7.30.1 (24.22.1), 8.12.2 (26.12.1). OpenSSL 3.5.9 in 22.23.4 and 24.22.1. c-ares 1.34.9 in all three. SQLite 3.53.4 in 22.23.4.
- 26.12.1 also reverts "module: synchronously load most ES modules" (commit e5cae10148).

### CVE records

- At 2026-10-22T06:01Z the CVE Services API returned `"state":"RESERVED"` for all ten IDs (`https://cveawg.mitre.org/api/cve-id/<id>`), and `CVE_RECORD_DNE` for the records. NVD (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`) returned no results. So there are no published CVE records and no CVSS scores yet; the severities above are the Node.js project's.

### Brotli upstream

- The cherry-picked commit is [google/brotli 0ed4268](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b), 2026-02-27, "Detect and report invalid stream earlier.", changing `c/dec/decode.c` and `c/include/brotli/decode.h`.
- Brotli published [v1.2.1](https://github.com/google/brotli/releases/tag/v1.2.1), v1.1.1 and v1.0.10 on 2026-10-21 between 19:26:58 and 19:27:34 UTC. Each release note says: "SECURITY - CVE-2026-111497: out-of-bounds write permits remote code execution".
- Debian builds Node against the system Brotli: `debian/rules` of nodejs 20.19.2+dfsg-1+deb13u2 (trixie) passes `--shared-brotli` (and `--shared`, `--shared-zlib`, `--shared-openssl`), and `debian/control` build-depends on `libbrotli-dev` ([sources.debian.org](https://sources.debian.org/src/nodejs/20.19.2+dfsg-1+deb13u2/debian/rules/)). For such builds the Brotli fix comes from the distribution's brotli package.
- At 2026-10-22 ~06:09Z the Debian security tracker had no page for CVE-2026-111497 (HTTP 404) and Ubuntu's notices API returned 0 notices for it.

## Who is exposed: code paths into the Brotli decoder

- `fetch()` in Node is undici: "The implementation is based upon undici" (`doc/api/globals.md` at v24.22.1).
- undici's fetch decodes `Content-Encoding: br` responses with `zlib.createBrotliDecompress` (`require('node:zlib')`): [deps/undici/src/lib/web/fetch/index.js at v24.22.1](https://github.com/nodejs/node/blob/v24.22.1/deps/undici/src/lib/web/fetch/index.js#L2256-L2260), and the same code at v22.23.4 (line 2164) and v26.12.1 (line 2322).
- The decoders are chosen from the response's `Content-Encoding` header only. The request's `Accept-Encoding` (`br, gzip, deflate` for https, `gzip, deflate` for http, same file lines 1523-1528) is not checked against it, so a server can send Brotli to a client that did not ask for it.
- axios in Node decompresses `br` responses unless `decompress: false`: [lib/adapters/http.js at v1.20.0](https://github.com/axios/axios/blob/v1.20.0/lib/adapters/http.js#L1179-L1209).
- body-parser 2.0.0 (2024-09-10) "Add brotli support" ([HISTORY.md](https://github.com/expressjs/body-parser/blob/master/HISTORY.md)); `inflate` "Defaults to `true`" (README); [lib/read.js at v2.3.0](https://github.com/expressjs/body-parser/blob/v2.3.0/lib/read.js#L190-L224) decompresses `br` request bodies and returns 415 when `inflate: false`. Express 5.3.0 depends on `body-parser ^2.3.0` and exports `express.json = bodyParser.json`. body-parser 1.20.8 (Express 4) handles only deflate, gzip and identity.
- The decoder is compiled into the `node` binary (`deps/brotli`), so updating an npm package such as `undici` does not change it.

## Release lines and images

- Node release schedule ([nodejs/Release schedule.json](https://github.com/nodejs/Release/blob/main/schedule.json)): v20 ended 2026-04-30, v25 ended 2026-06-01; v22 ends 2027-04-30, v24 ends 2028-04-30; v26 becomes LTS on 2026-10-28.
- docker-library/official-images commit 74ff70c42b, "Node: feat: Node.js 22.23.4, 24.22.1, 26.12.1", at 2026-10-21T10:48:56Z. The `library/node` file no longer lists tags for 20 or 25.
- Our scan of 24 official `node` tags for linux/amd64 and linux/arm64, from registry metadata only: `results/registry-20261022T062338Z.json`, summary in `results/registry-20261022T062338Z-summary.txt`. Docker Hub's per-image `last_pushed` is metadata, not proof of when a tag first served an image.

## pm2 and nvm behavior

- pm2 docs, [Startup](https://pm2.keymetrics.io/docs/usage/startup/): "When you upgrade the local Node.js version, be sure to update the PM2 startup script, so it runs the latest Node.js binary you have installed", with `pm2 unstartup` then `pm2 startup`; and "save the app list so it will respawn after reboot: pm2 save".
- pm2 docs, [Updating PM2](https://pm2.keymetrics.io/docs/usage/update-pm2/): "update the in-memory PM2 daemon via command: pm2 update".
- pm2 6.0.14 CLI: `-a --update-env` "force an update of the environment with restart/reload" (`lib/binaries/CLI.js` line 49).
- pm2 6.0.14 `lib/Common.js` `resolveInterpreter`: a `.js` script gets the interpreter `node` (from `lib/API/interpreter.json`), resolved through the app's environment when spawned; a script without a known extension that is not a binary gets `process.execPath`, the absolute path of the Node running the pm2 CLI. `lib/God/ForkMode.js` spawns the interpreter with the app's saved environment.
- pm2 cluster mode: `lib/God/ClusterMode.js` calls `cluster.fork()`, and Node's cluster primary forks workers with `child_process.fork()` (`lib/internal/cluster/primary.js` at v24.22.1), which defaults `execPath` to `process.execPath` (`lib/child_process.js` line 144). So cluster-mode workers run on the daemon's Node whatever the entry's interpreter or PATH says. The lab shows it: the `clustered` app stayed on v24.14.0 after `restart --update-env` and moved only after `pm2 update`.
- nvm README: "New shells will start with the default version of node (e.g., `nvm alias default`)", and `nvm install --reinstall-packages-from=...` to move global npm packages to the new version.
- `results/pm2-lab-20261022T063002Z.txt`: the lab that shows each of these on a real pm2 6.0.14 with Node v24.14.0 and v24.22.1 (`lab/pm2-pin-lab.sh`), four apps: bare `node`, `npm start`, an absolute `--interpreter` and cluster mode.

## Our own runs

- `results/pgrep-vs-proc-20261022T063334Z.txt`: on the Pi, `pgrep -c node` and `pgrep -c -x node` both returned 0 while five processes ran a `node` binary, named `PM2 v6.0.14: Go`, `MainThread` and `next-server (v1` in `/proc/<pid>/comm`.

- `examples/run-20261022T062905Z.txt` and `.json`: `node_runtime_audit.py --redact` on the Raspberry Pi we build on, 2026-10-22T06:29:05Z, as a normal user.
- The production upgrade described in the post (six Node apps under pm2, installed with nvm) was done by the team on 21 October. Its details come from that work and are generalized; the lab reproduces the pm2 behaviors on a separate machine.
