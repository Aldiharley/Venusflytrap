# DQ4 (external WAF baselines on byte-identical replays): measured results

DQ4 changes no detection. It adds a stdlib-only replayer (`eval/replay_external.py`), a Docker
Compose file with two CRS engines in front of one stand-in upstream (`eval/baselines/`), a driver for
the CRS settings and for Venusflytrap's own proxy (`eval/baselines/run_settings.py`), and a report
script (`eval/dq4_report.py`). Every number below was copied from the run output named next to it;
all of them live in the git-ignored `.superpowers/dq4/runs/` of the measuring worktree, and file
names below are relative to that directory. The plan is
[`docs/superpowers/plans/2026-10-28-dq4-external-baselines.md`](../docs/superpowers/plans/2026-10-28-dq4-external-baselines.md).

- **Measured tree:** main at `01b1484` (after DQ3 rule C); release build of `venusflytrap`.
- **Machine:** the Windows 11 host of [`RESULTS-DQ1.md`](RESULTS-DQ1.md), Docker Desktop 29.6.2.
- **Corpus:** blazehttp test cases, commit `afc88a94`. The commit lists 33,877 test files (658
  `.black`, 33,219 `.white`; `expected-files.txt`). Two are absent on disk, deleted by the host
  antivirus, so every run here scores the 33,875 files present (`dq4-report.json`,
  `corpus_missing`):
  - `3e/f0/ba59dd0840009f5b678663dbb1bd.black`
  - `d5/65/2dcdd89317f10d43500014509120.black`

  These are the two files `docs/BENCHMARK.md` already lists as unreadable. No file went missing
  between runs, so all runs share the same rows.

## Engines and images

| Engine | Image (tag) | Digest | Inside |
|---|---|---|---|
| ModSecurity v3 + CRS | `owasp/modsecurity-crs:4.30.0-nginx-202610180210` | `sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d` | libmodsecurity 3.0.17, nginx 1.30.6, CRS 4.30.0 |
| Coraza + CRS | `ghcr.io/coreruleset/coraza-crs:4.30.0-caddy-alpine-202610271210` | `sha256:20294a0df7b6cf1db4b419e6a35757cd133960fc26a615e4c7c8850a154eefea` | Caddy v2.11.6 with the Coraza module, CRS 4.30.0 |

Both digests are the `RepoDigests` of the pulled images, and both are pinned in
`eval/baselines/docker-compose.yml`. No other image was pulled. The Coraza image is the one the
CRS project publishes, built on coraza-caddy. `ghcr.io/corazawaf/coraza-caddy` was not used:
the registry refused an anonymous pull token for it (HTTP 403). Both engines run the same CRS
version, 4.30.0, so CRS-version differences play no part in any engine difference below.

**Topology.** One stand-in upstream answers every request with an empty 200. It is the nginx
binary of the ModSecurity image, run with `eval/baselines/upstream.conf`, without the ModSecurity
module. Both WAFs proxy to it over an internal Docker network. Only the two WAF ports are
published, and only on `127.0.0.1` (18080 ModSecurity, 18081 Coraza).

Venusflytrap runs as its real proxy (`venusflytrap serve`, enforcing) on `127.0.0.1:18089`, in
front of the replayer's stand-in upstream. That upstream drains each body and answers 200 with
keep-alive. The config is `vft-dq4.yaml`, which only sets `proxy.trusted_proxies: ["127.0.0.1"]`.
That is the setting `eval --mode tcp` uses, so every request is its own source; everything else
is the default config.

**Settings.** Each CRS setting is one container start with these variables. The driver then read
the active (uncommented) `setvar` lines back from the container's `crs-setup.conf`, saved as
`effective_crs_setup` in each `<run>.json`:

- ModSecurity: `BLOCKING_PARANOIA=<PL>`, `ANOMALY_INBOUND=<T>`. The effective values are
  `tx.blocking_paranoia_level=<PL>` and `tx.inbound_anomaly_score_threshold=<T>`, with
  `outbound_anomaly_score_threshold=4`.
- Coraza: `PARANOIA=<PL>`, `BLOCKING_PARANOIA=<PL>`, `ANOMALY_INBOUND=<T>`. The effective values
  are the same three.
- `detection_paranoia_level` is not set, so it defaults to the blocking level.
- Both engines also get `*_REQ_BODY_LIMIT=1048576` and `*_REQ_BODY_NOFILES_LIMIT=1048576`, which
  equal Venusflytrap's 1 MiB `limits.max_body`, and `*_AUDIT_LOG_PARTS=ABHZ`. ABHZ keeps headers
  and rule messages but no bodies, so audit records stay under Docker's 16 KiB log-line split.
- Every other variable is the image default, including `MODSEC_ARGUMENTS_LIMIT=1000` and the
  engines' own body-parse rules.

## Replay method

`eval/replay_external.py` ports the TCP mode's rules from `crates/vft-cli/src/eval.rs`:

- **Corpus walk:** sorted by rel path, unreadable files skipped.
- **Framing (`rewrite_for_replay`):** CRLF lines; the file's own `Connection`, `Content-Length`,
  `X-Forwarded-For`, `Keep-Alive` and `Proxy-Connection` are dropped; then
  `X-Forwarded-For: 10.x.y.z` (sample index), `Connection: close` and an exact `Content-Length`
  are added. `Transfer-Encoding` or `Upgrade` makes a request not replayable.
- **Parse check (`parse_raw`):** a request the Rust parser would refuse is skipped.

The files are therefore not sent verbatim. Many use bare LF line ends or a stale `Content-Length`,
and a stale length desynchronises any HTTP/1.1 server. Instead, every engine gets exactly the
bytes Venusflytrap's TCP mode sends, and the replayer proves it. Each run's JSON records
`sent_sha256`, a digest over every rel path and the SHA-256 of its sent bytes. It is
`8e9b2274b9361a50fb5984f0600afa161dc58724e22bffacc0323b003e7a20a4` in all 17 runs: 16 CRS runs and
`vft-serve.json`.

**Request set.** The Python rules select the same set as the Rust TCP mode: 33,711 replayed and
164 not replayable, all 164 for `Transfer-Encoding`/`Upgrade`. The Rust run (`vft-tcp.json`) also
has `replayed` 33,711 and `not_replayable` 164. All 164 are benign files, so the shared rows hold
all 656 malicious and 33,055 benign files.

**Connections.** Each request gets its own connection: 8 worker threads, zero-linger client
sockets (RST on close, no `TIME_WAIT`), and a 10 s limit each for connect, write and read, the same
as `REPLAY_IO_TIMEOUT`.

**Outcomes.**

- `blocked`: status 403.
- `passed`: status 200 from the upstream.
- `failed`: any other status, or an I/O error with no status line.

A failed row is never counted as blocked. It is a negative in every TP/FP/TN/FN below.

**Rule ids** come from each WAF's JSON audit log, joined on the per-request `X-Forwarded-For`
(`rules-<run>.json`: rel path to rule ids; no payload text).

## Recall and FP rate, all engines, same 33,711 rows

Venusflytrap appears twice:

- `vft-library` is `eval --mode library` (`vft-library.csv`) restricted to the replayed rows.
- `vft-serve` is Venusflytrap's proxy behind the same replay.

The intervals are Wilson 95 %. `failed` is counted inside FN or TN. `io` is the number of failed
rows with no status line. Source: `dq4-report.json`, and the run CSV and JSON named in each row.

| Engine, setting | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] | failed (benign / malicious) | io | Source |
|---|---|---|---|---|---|---|---|---|---|
| vft-library | 288 | 188 | 32,867 | 368 | 43.90 % [40.15, 47.72] | 0.57 % [0.49, 0.66] | - / - | - | `vft-library.csv` |
| vft-serve | 287 | 186 | 32,869 | 369 | 43.75 % [40.00, 47.57] | 0.56 % [0.49, 0.65] | 2 / 3 | 0 | `vft-serve.csv`, `vft-serve.json` |
| modsecurity PL1 T5 | 514 | 4,950 | 28,105 | 142 | 78.35 % [75.04, 81.34] | 14.98 % [14.59, 15.36] | 29 / 4 | 0 | `modsecurity-pl1-t5.{csv,json}` |
| modsecurity PL2 T5 | 587 | 10,963 | 22,092 | 69 | 89.48 % [86.90, 91.60] | 33.17 % [32.66, 33.68] | 29 / 4 | 0 | `modsecurity-pl2-t5.{csv,json}` |
| modsecurity PL3 T5 | 612 | 13,437 | 19,618 | 44 | 93.29 % [91.12, 94.97] | 40.65 % [40.12, 41.18] | 29 / 4 | 0 | `modsecurity-pl3-t5.{csv,json}` |
| modsecurity PL4 T5 | 622 | 16,277 | 16,778 | 34 | 94.82 % [92.84, 96.27] | 49.24 % [48.70, 49.78] | 29 / 4 | 0 | `modsecurity-pl4-t5.{csv,json}` |
| modsecurity PL1 T10 | 350 | 758 | 32,297 | 306 | 53.35 % [49.53, 57.14] | 2.29 % [2.14, 2.46] | 29 / 4 | 0 | `modsecurity-pl1-t10.{csv,json}` |
| modsecurity PL1 T20 | 165 | 185 | 32,870 | 491 | 25.15 % [21.98, 28.61] | 0.56 % [0.48, 0.65] | 29 / 4 | 0 | `modsecurity-pl1-t20.{csv,json}` |
| modsecurity PL2 T10 | 504 | 5,897 | 27,158 | 152 | 76.83 % [73.45, 79.90] | 17.84 % [17.43, 18.26] | 29 / 4 | 0 | `modsecurity-pl2-t10.{csv,json}` |
| modsecurity PL2 T20 | 357 | 3,268 | 29,787 | 299 | 54.42 % [50.59, 58.20] | 9.89 % [9.57, 10.21] | 29 / 4 | 0 | `modsecurity-pl2-t20.{csv,json}` |
| coraza PL1 T5 | 515 | 4,984 | 28,071 | 141 | 78.51 % [75.20, 81.48] | 15.08 % [14.70, 15.47] | 12 / 5 | 0 | `coraza-pl1-t5.{csv,json}` |
| coraza PL2 T5 | 586 | 10,979 | 22,076 | 70 | 89.33 % [86.73, 91.47] | 33.21 % [32.71, 33.72] | 13 / 5 | 1 | `coraza-pl2-t5.{csv,json}` |
| coraza PL3 T5 | 605 | 13,445 | 19,610 | 51 | 92.23 % [89.92, 94.04] | 40.67 % [40.15, 41.21] | 13 / 5 | 1 | `coraza-pl3-t5.{csv,json}` |
| coraza PL4 T5 | 616 | 15,118 | 17,937 | 40 | 93.90 % [91.80, 95.49] | 45.74 % [45.20, 46.27] | 14 / 5 | 2 | `coraza-pl4-t5.{csv,json}` |
| coraza PL1 T10 | 344 | 2,843 | 30,212 | 312 | 52.44 % [48.61, 56.24] | 8.60 % [8.30, 8.91] | 12 / 5 | 0 | `coraza-pl1-t10.{csv,json}` |
| coraza PL1 T20 | 182 | 604 | 32,451 | 474 | 27.74 % [24.45, 31.29] | 1.83 % [1.69, 1.98] | 12 / 5 | 0 | `coraza-pl1-t20.{csv,json}` |
| coraza PL2 T10 | 502 | 8,791 | 24,264 | 154 | 76.52 % [73.13, 79.61] | 26.60 % [26.12, 27.07] | 13 / 5 | 1 | `coraza-pl2-t10.{csv,json}` |
| coraza PL2 T20 | 377 | 6,238 | 26,817 | 279 | 57.47 % [53.65, 61.20] | 18.87 % [18.45, 19.30] | 13 / 5 | 1 | `coraza-pl2-t20.{csv,json}` |

**Venusflytrap's full-corpus figures** cover all 33,875 rows, including the 164 that cannot be
replayed: TP 288, FP 188, TN 33,031, FN 368. That is recall 43.90 % [40.15, 47.72] and FP rate
0.57 % [0.49, 0.65] (`vft-library.json`). They match the shared-row figures because the 164 rows
hold no Venusflytrap false positive.

**`vft-serve` against `vft-library`.** `vft-serve` blocks no row that `vft-library` allows. Three
rows that the library blocks were refused by the proxy's HTTP front end with 400 or 413 before
inspection, so they count as failed (`dq4-report.json`, `disagree_with_library`). These are the
same `proxy_rejected` rows as in the Rust TCP replay: 473 blocked rows equal its `matched_block`
473, and its `mismatched` is 0 (`vft-tcp.json`).

**What the failed rows are.**

- **ModSecurity (identical in every setting, 33 rows):**
  - 18 benign rows got 414 from nginx's own 8 KiB request-line limit, before ModSecurity ran.
  - 14 rows got 400 from ModSecurity's own rules, outside CRS: 8 from 200002 (request body parse
    error), 5 from 200007 (more than 1,000 arguments) and 1 from 200003 (multipart strictness).
  - 1 malicious row got 400 with no joined audit record; its cause was not examined.
  - Source: `modsecurity-pl1-t5.csv`, `rules-modsecurity-pl1-t5.json`.
  - Counting ModSecurity's own 400 denies as blocks would add at most 3 TP and 11 FP to any
    ModSecurity row.
- **Coraza:**
  - 16 rows got 400 (10 from 200002, 5 from 200007, 1 with no record).
  - 1 benign row got 413 (body over 1 MiB).
  - The `io` rows (see below) make up the rest.
  - Source: `coraza-pl1-t5.csv`, `rules-coraza-pl1-t5.json`.

**io.** ModSecurity and Venusflytrap had 0 `io` rows in every run. Coraza had 0 at PL1 and 1 or 2
at PL2 and above, 6 across its 8 runs. They are always one or both of the two largest benign
bodies: `11/27/9e27efe2a7cf63decdd16ed80f7c.white` (858 KB) and
`09/8a/171355d4b76706b9e4be0a80519a.white` (573 KB) (`io_examples` in each `coraza-*.json`).
Coraza needs about 8 to 14 s to answer these, so a client limit of 10 s sometimes times out. A
re-send with a 120 s limit got 403 for both
(`coraza-upstream-8k/coraza-pl2-t20-io-probe.txt`). Each `io` row is therefore at most one
uncounted FP (≤ 0.006 points of FP rate).

**One harness correction during the run.** The first pass of all 8 Coraza settings ran with nginx's
default 8 KiB request-line buffers in the stand-in upstream. Coraza (Caddy) passed up to 13 long-URI
benign rows that the upstream then refused with 414. These are benign rows that are not blocked
either way, so TP and FP were already right. Those outputs are kept in `coraza-upstream-8k/`.

The upstream now accepts lines up to 1 MiB, and all 8 Coraza settings were re-run. Against the
first pass, TP is unchanged in all 8 settings and FP in 7. In PL3 T5, one `io` row became a 403,
so FP is 13,445 instead of 13,444. The ModSecurity runs were not affected, because ModSecurity's
nginx front end applies the same 8 KiB limit before proxying. A re-run of ModSecurity PL1 T5 with
the new upstream produced a byte-identical CSV (`modsecurity-pl1-t5.csv` against
`modsecurity-pl1-t5.upstream-8k.csv`).

## TPR at matched FPR

The target is Venusflytrap's full-corpus FP rate, 0.566 % (188 / 33,219; 0.569 % on the shared
rows). For each engine, the CRS setting nearest to it (`dq4-report.json`, `matched_fpr`) is:

- **ModSecurity PL1 T20:** FP rate 0.56 % [0.48, 0.65], a matched FPR. Its TPR is 25.15 %
  [21.98, 28.61], against Venusflytrap's 43.90 % [40.15, 47.72] on the same rows. The intervals
  do not overlap.
- **Coraza PL1 T20:** FP rate 1.83 % [1.69, 1.98], about 3.2 times Venusflytrap's, so this is not a
  matched point. Its TPR is 27.74 % [24.45, 31.29]. Coraza reaches no setting nearer to 0.57 % in
  this grid.

The CRS curve is coarse at this end. PL1 T10 is at 2.29 % FPR and 53.35 % TPR (ModSecurity), and
PL1 T20 at 0.56 % and 25.15 %. No ModSecurity setting in the grid reaches Venusflytrap's recall
at or below its FP rate. Thresholds between 10 and 20 were not measured.

## McNemar against Venusflytrap (paired, same rows)

The test is exact two-sided McNemar on the 33,711 shared rows, against Venusflytrap's library
verdicts (`vft-library.csv`). It is computed per class: b = rows blocked by the CRS setting only,
c = rows blocked by Venusflytrap only. Source: `dq4-report.json`, `mcnemar_vs_vft_library`. The
same test against `vft-serve.csv` (`mcnemar_vs_vft_serve`) moves b or c by at most 2 and changes no
conclusion. "< 1e-300" means the p-value underflows a double.

| CRS setting | malicious b / c | p | benign b / c | p |
|---|---|---|---|---|
| modsecurity PL1 T5 | 247 / 21 | 3.95e-50 | 4,830 / 68 | < 1e-300 |
| modsecurity PL2 T5 | 312 / 13 | 1.73e-75 | 10,777 / 2 | < 1e-300 |
| modsecurity PL3 T5 | 337 / 13 | 1.37e-82 | 13,249 / 0 | < 1e-300 |
| modsecurity PL4 T5 | 345 / 11 | 3.51e-87 | 16,089 / 0 | < 1e-300 |
| modsecurity PL1 T10 | 129 / 67 | 1.12e-05 | 696 / 126 | 2.81e-96 |
| **modsecurity PL1 T20** (matched FPR) | **42 / 165** | **1.97e-18** | **161 / 164** | **0.912** |
| modsecurity PL2 T10 | 240 / 24 | 5.4e-46 | 5,730 / 21 | < 1e-300 |
| modsecurity PL2 T20 | 146 / 77 | 4.47e-06 | 3,163 / 83 | < 1e-300 |
| coraza PL1 T5 | 247 / 20 | 6.16e-51 | 4,865 / 69 | < 1e-300 |
| coraza PL2 T5 | 310 / 12 | 5.13e-76 | 10,794 / 3 | < 1e-300 |
| coraza PL3 T5 | 329 / 12 | 1.97e-81 | 13,258 / 1 | < 1e-300 |
| coraza PL4 T5 | 338 / 10 | 2.26e-86 | 14,931 / 1 | < 1e-300 |
| coraza PL1 T10 | 124 / 68 | 6.46e-05 | 2,758 / 103 | < 1e-300 |
| coraza PL1 T20 | 51 / 157 | 9.46e-14 | 576 / 160 | 6.24e-56 |
| coraza PL2 T10 | 237 / 23 | 5.94e-46 | 8,608 / 5 | < 1e-300 |
| coraza PL2 T20 | 159 / 70 | 3.89e-09 | 6,102 / 52 | < 1e-300 |

At the matched FPR the two engines are statistically indistinguishable on benign rows: 161 against
164 discordant false positives, p = 0.91. On malicious rows, Venusflytrap alone blocks 165
attacks and ModSecurity PL1 T20 alone blocks 42 (p = 2.0e-18). The 42 are attacks that CRS
catches and Venusflytrap misses, so the two engines miss different attacks. Every setting with
higher CRS recall (PL1 T5 to PL4, PL1 T10, PL2 T10/T20) also has a significantly higher FP rate
than Venusflytrap.

ModSecurity and Coraza at PL1 T5 differ on 1 malicious row (0 / 1, p = 1.0) and 36 benign rows
(1 / 35, p = 1.1e-09; `mcnemar_modsecurity_vs_coraza_pl1_t5`).

## CRS false positives by rule family (summary counts)

A family is the first three digits of a rule id. 949, 959 and 980 (anomaly evaluation and
reporting) and 901 and 905 (setup) are not counted as families. A row counts once per family that
fired on it. Source: `dq4-report.json`, `fp_by_family` of each run.

| Run | FP rows | no joined record | with 920 | 920 only | without 920 | rows by family (fired) | top rule ids (FP rows) |
|---|---|---|---|---|---|---|---|
| modsecurity PL1 T5 | 4,950 | 15 | 3,735 | 3,686 | 1,200 | 920: 3,735; 942: 559; 943: 442; 932: 178; 930: 105; 941: 84; 911: 58; 921: 19; others ≤ 13 | 920420: 3,633; 942550: 480; 943110: 442; 920450: 230; 930130: 80 |
| coraza PL1 T5 | 4,984 | 0 | 3,747 | 1,392 | 1,237 | 920: 3,747; 921: 1,718; 942: 913; 943: 449; 932: 357; 941: 326; 930: 141; others ≤ 59 | 920420: 3,635; 921150: 1,699; 942550: 750; 920250: 648; 943110: 445 |
| modsecurity PL1 T20 | 185 | 12 | 4 | 0 | 169 | 942: 146; 943: 50; 941: 35; 932: 27; 921: 8; others ≤ 6 | 942550: 132; 943110: 50; 941100: 25; 941160: 23; 932160: 11 |
| coraza PL1 T20 | 604 | 0 | 413 | 35 | 191 | 920: 413; 921: 328; 942: 251; 932: 83; 941: 65; 943: 59; others ≤ 24 | 920420: 367; 920270: 346; 920250: 345; 921150: 323; 920450: 231 |

What the families show:

- **ModSecurity PL1 T5.** Protocol enforcement (920) alone explains 3,686 of the 4,950 false
  positives (74 %). Almost all of these come from 920420, the request content type is not in the
  CRS allow-list (3,633 rows). The remaining 1,264 FP rows give an FP rate of 3.82 % (1,264 /
  33,055). They split into 1,200 rows with an attack family and none from 920, plus 49 with both
  920 and another family, plus the 15 without a joined record.
- **The two engines run identical CRS 4.30.0 rules but score differently.** Coraza raises 921150
  (CR/LF in argument names) on 1,699 benign rows and 920250/920270 (UTF-8 and character-range
  checks) on 648 and 400. ModSecurity raises 921 on 19 rows. Those extra points are why Coraza's
  FP rate falls much less than ModSecurity's as the threshold rises (8.60 % against 2.29 % at T10,
  1.83 % against 0.56 % at T20). The cause, presumably different argument and encoding parsing in
  the two engines, was not investigated.
- **Missing records.** The "no joined record" rows are blocked rows whose audit record was not
  found: 15 at ModSecurity PL1 T5, 12 at PL1 T20. A record that Docker split despite parts ABHZ is
  one possible cause; this was not confirmed.

The other twelve settings' family counts are in the same file.

## How to reproduce

From the repository root, with the corpus at `<corpus>`:

```
cargo build --release -p vft-cli
target/release/venusflytrap eval --corpus <corpus> --mode library --out .superpowers/dq4/runs/vft-library.csv
target/release/venusflytrap eval --corpus <corpus> --mode tcp --limit 40000          # > vft-tcp.json
docker compose -f eval/baselines/docker-compose.yml up -d
py -I -X utf8 eval/baselines/run_settings.py --corpus <corpus> --out .superpowers/dq4/runs --engine modsecurity --engine coraza
py -I -X utf8 eval/baselines/run_settings.py --corpus <corpus> --out .superpowers/dq4/runs --engine vft
docker compose -f eval/baselines/docker-compose.yml down
py -I -X utf8 eval/dq4_report.py --runs .superpowers/dq4/runs --vft-library .superpowers/dq4/runs/vft-library.csv --expected <list> > dq4-report.json
```

The CRS runs took 46 to 181 s each (`wall_s` in each JSON), the Venusflytrap replay 27 s.

## What this does not show

- **One corpus.** The large CRS false-positive rate at PL1 T5 is mostly 920420 (content type not
  allowed). A deployment would tune that rule to its own content types; this report does not tune
  CRS, so it measures CRS as shipped.
- **A coarse CRS curve.** CRS ran at eight points, so TPR at matched FPR is one nearest point and
  not an interpolation. Venusflytrap was measured at its shipped thresholds only.
- **No audit-log recomputation.** The paranoia and threshold curves come from separate blocking
  runs. They were not recomputed offline from one detection-only run.
- **A corpus artefact favours CRS.** Rule 920350 (numeric-IP Host) fires on 84 % of dev attack
  rows and 0.18 % of dev benign rows, because of how the corpus was recorded. It gives attack rows
  anomaly points unrelated to the attack, so CRS recall here is inflated by an unmeasured amount.
  See [`RESULTS-DQ5-fixes.md`](RESULTS-DQ5-fixes.md).
- **SafeLine** is out of scope until the owner reviews its terms.

## Other checks run

- `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` were green, exit 0
  (`cargo-checks.txt`).
- `py -I -X utf8 -m unittest discover -s eval -p "test_*.py"` ran 62 tests, all OK. That includes
  13 new replayer tests, which run against local socket stand-ins, and 4 report tests.
- All containers and networks were removed with `docker compose down`, and no replay, proxy or
  upstream process was left running.
