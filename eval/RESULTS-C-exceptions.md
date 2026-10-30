# Sub-project C (scoped exceptions): no-change check and a measured Referer exception

Sub-project C adds an exceptions file (`--exceptions <file>`) with three tiers: `ignore`, `log-only` and
`skip-inspection`. With no file, nothing changes. This note records two things: the check that the
default configuration is unchanged, and what one example exception, `eval/exceptions/referer-sql.yaml`,
does to recall and to false positives. Every number below was copied from a run made for this note.

## Setup

- **Baseline binary:** `main-db7177b.exe`, built from main `db7177b` (the merge base of the branch).
- **Measured binary:** branch `c-exceptions` at `70632be`, `cargo build --release -p vft-cli`.
- **Corpus:** the blazehttp corpus with the dev/held-out split manifest (sha256 prefix `06d8905d897ba1a`).
  Dev has 16,938 rows (328 malicious, 16,610 benign); held-out has 16,937 rows (328 malicious,
  16,609 benign).
- **Exception file:** `eval/exceptions/referer-sql.yaml`: action `ignore`, constructs `sqli.*`, scope
  `path_prefix: /` and `field: { loc: header, name: referer }`. `sqli.*` expands to 15 constructs (the
  SQL sinks, `sqli.sql-keyword`, `sig.classic-or`, `sig.union-all-select`, `sig.schema-enum` and
  `api.type-violation`, whose family is SQL injection). `exceptions check --as-of 2026-10-30` prints one
  `live` line and exits 0.
- **As-of date:** `2026-10-30` (`--as-of`), so the entry is live for every request of the run.
- **Order of work:** the no-change checks, then the dev A/B, then the held-out run. Held-out was scored
  once per side (without and with the file), after the dev A/B was written down. The file was not
  changed after the held-out run. Its `reason` text was set before any A/B run (see "The count in the
  reason text").

## No change without a file

### Dev A/B (library mode, 16,938 shared rows)

`bash eval/ab_dev.sh c-nochange "" "" <main-db7177b.exe> ./target/release/venusflytrap.exe`:

```
ab: 16938 shared rows, 0 only in a, 0 only in b
delta: tp=+0 fp=+0
mcnemar lib_verdict malicious: b=0 c=0 p=1
mcnemar lib_verdict benign: b=0 c=0 p=1
a: tp=150 fp=100 tn=16510 fn=178 recall=45.73% [40.42%, 51.14%] fp_rate=0.602% [0.495%, 0.732%]
b: tp=150 fp=100 tn=16510 fn=178 recall=45.73% [40.42%, 51.14%] fp_rate=0.602% [0.495%, 0.732%]
fallen: 0 malicious rows from Challenge/Block to Allow/Monitor
```

A column-by-column comparison of the two CSVs (`lib_verdict`, `serve_verdict`, `score`, `banned`,
`constructs`, `cause`, `field`, `top`, `shadow`, `top_field`, all 16,938 rows) found 0 differing cells.

### Serve-mode decision diff (full corpus)

`eval --mode serve --sources distinct` and `--sources pooled:100` with the baseline binary and with the
branch binary, then `eval/compare_runs.py` and `eval/changes.py gate` (the same steps as
`eval/decision_gate.sh check` and `diff`, which cannot take a baseline binary).

| Sources | Shared rows | TP | FP | TN | FN | Changed decisions | Score-only changes | bans_from_allowed | invariant_violations |
|---|---|---|---|---|---|---|---|---|---|
| `distinct` | 33,875 | 294 | 189 | 33,030 | 362 | 0 | 0 | 0 | 0 |
| `pooled:100` | 33,875 | 294 | 189 | 33,030 | 362 | 0 | 0 | 0 | 0 |

`compare_runs.py` printed `delta: tp=+0 fp=+0` and `decision diffs: 0` for both. A cell-by-cell
comparison of each pair of CSVs (all columns, 33,875 rows) found 0 differing cells.

## The count in the reason text

The example file's `reason` first said "43 of 100 dev FPs (DQ2)", a figure from `RESULTS-DQ2.md`. It was
re-counted on the no-exception dev run (`c-nochange-a.csv`): of the 100 dev false positives, the number
whose deciding field is the `Referer` header and whose deciding construct is `sqli.*` is **43** (25
`sqli.union-select` and 18 `sqli.boolean-tautology`). The old figure was 43 of 100 and the new one is
43 of 100: the same. The file now says "43 of the 100 dev FPs are decided by an sqli.* construct in the
Referer header (measured, eval/RESULTS-C-exceptions.md)". The other 57 dev false positives are in other
fields (the `bq` and `q` query parameters, request bodies, JSON leaves).

## Referer exception: dev

`bash eval/ab_dev.sh c-referer "" "--exceptions eval/exceptions/referer-sql.yaml --as-of 2026-10-30"`,
same binary on both sides.

| Run | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|---|---|
| without the file | 150 | 100 | 16,510 | 178 | 45.73 % [40.42, 51.14] | 0.602 % [0.495, 0.732] |
| with the file | 149 | 57 | 16,553 | 179 | 45.43 % [40.12, 50.84] | 0.343 % [0.265, 0.444] |
| change | -1 | -43 | | | -0.30 points | -0.259 points |

- McNemar (exact, two-sided) on malicious rows: b = 1 blocked only without the file, c = 0, p = 1.
- McNemar on benign rows: b = 43, c = 0, p = 2.274e-13.
- The test for the change is the paired McNemar test above, not the overlap of the two runs' intervals
  (the Wilson 95 % intervals in the table are each run's own, from the JSON reports). All 43 benign rows
  that changed went from false positive to not, and none went the other way, so the FP-rate change is
  not noise. The one lost true positive is a single row.

## Referer exception: held-out, scored once per side

`eval --mode library --manifest ... --side heldout`, once without and once with
`--exceptions eval/exceptions/referer-sql.yaml --as-of 2026-10-30`; `eval/changes.py ab` on the two runs
(16,937 shared rows).

| Run | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|---|---|
| without the file | 144 | 89 | 16,520 | 184 | 43.90 % [38.63, 49.31] | 0.536 % [0.436, 0.659] |
| with the file | 141 | 63 | 16,546 | 187 | 42.99 % [37.74, 48.40] | 0.379 % [0.297, 0.485] |
| change | -3 | -26 | | | -0.91 points | -0.157 points |

- McNemar on malicious rows: b = 3, c = 0, p = 0.25.
- McNemar on benign rows: b = 26, c = 0, p = 2.98e-08.
- 27 held-out false positives were decided by `sqli.*` in the `Referer`. 26 stopped being false positives.
  The 27th (`17/f5/7b239973ff77ba2cf8eb6c937a18.white`) has the same construct in a JSON body leaf as
  well, so it stays a Block.

## Changed rows

Counts are changed decisions between the run without and the run with the file (`lib_verdict` changed),
by label, deciding construct and field. Every row is in the run directory's `c-referer-changed.txt` and
`c-heldout-changed.txt`; the rows are named by `rel` only.

| Half | Label | Change | Deciding construct, field | Rows |
|---|---|---|---|---|
| dev | benign | Block to Allow | `sqli.union-select`, `header:referer` | 25 |
| dev | benign | Block to Monitor | `sqli.boolean-tautology`, `header:referer` | 17 |
| dev | benign | Block to Allow | `sqli.boolean-tautology`, `header:referer` | 1 |
| dev | benign | Monitor to Allow | `cmd.shell-meta`, `header:sec-ch-ua` | 10 |
| dev | malicious | Block to Allow (lost TP) | `sqli.boolean-tautology`, `header:referer` | 1 |
| dev | malicious | Monitor to Allow (a miss before and after) | `sqli.sql-keyword`, `query:id` | 1 |
| held-out | benign | Block to Allow | `sqli.union-select`, `header:referer` | 15 |
| held-out | benign | Block to Monitor | `sqli.boolean-tautology` (10), `sqli.union-select` (1), `header:referer` | 11 |
| held-out | benign | Monitor to Allow | `cmd.shell-meta`, `header:sec-ch-ua` | 7 |
| held-out | malicious | Block to Allow (lost TP) | `sqli.boolean-tautology` (2), `sqli.union-select` (1), `header:referer` | 3 |

Dev: 55 changed decisions (3 more rows moved score only). Held-out: 36 changed decisions (5 score-only).
Of the benign rows, 43 (dev) and 26 (held-out) stopped being false positives; 17 and 11 of them fell to
Monitor, not Allow, because other latents still score 41 to 43 (`cmd.shell-meta` on the same request).
The benign Monitor count moved from 793 to 800 on dev and from 810 to 814 on held-out: Block-to-Monitor
rows add to it, and the `sec-ch-ua` Monitor-to-Allow rows subtract from it. Those 10 and 7 rows were
Monitor because the `sqli.*` latents in the `Referer` corroborated a `cmd.shell-meta` latent in
`sec-ch-ua`; without them the corroboration is gone and the score drops from 41 to 39.

### Every lost true positive

All four lost TPs are Block to Allow, and the score fell to 36 (below the Monitor threshold):

| Half | Row | Deciding construct before | Where the attack is |
|---|---|---|---|
| dev | `e7/06/ec824dd3bbca23314d8c46b75fa8.black` | `sqli.boolean-tautology`, `header:referer` | `GET /vulnerabilities/sqli_blind/?id=`: the query is empty; the payload is in the `Referer` only |
| held-out | `93/a4/c95053943540e32018c5f4327785.black` | `sqli.boolean-tautology`, `header:referer` | `GET /vulnerabilities/sqli/?id=1+and+1%3D2...`: with the `Referer` ignored, no `sqli.*` construct remains in the request's own fields |
| held-out | `b1/71/3c058c3be65f080c2443252dab2b.black` | `sqli.boolean-tautology`, `header:referer` | `GET /vulnerabilities/fi/?page=include.php`: nothing else in the request is an SQL construct |
| held-out | `fa/70/e421b47e839db0c703707daf5d18.black` | `sqli.union-select`, `header:referer` | `GET /vulnerabilities/sqli/?id=&Submit=Submit`: the query is empty; the payload is in the `Referer` only |

The fifth malicious row that changed on dev (`22/8a/a904b637da933d7a86928334f05f.black`) was a Monitor
before and is an Allow after (score 40 to 39). It was a miss in both runs and is not a lost TP.

## What the exception costs in recall

Ignoring `sqli.*` in the `Referer` header removes four true positives out of the 656 malicious rows
across both halves (1 of 328 on dev, 3 of 328 on held-out), and removes 69 false positives out of 189
(43 of 100 on dev, 26 of 89 on held-out). The lost TPs are the corpus's test-application rows in which
the attack URL appears as the `Referer` of the next request; the corpus recorded those requests with the
previous page in the `Referer`, and nothing in the request's own query or body is flagged. They are
caught only because of the `Referer`. A real deployment sees the same pattern whenever an attacker sends
a payload in a `Referer` header, and that detection is gone for as long as the exception is live. The
scope is every path and every method, so this holds on all routes, not only search pages. The recall
change on held-out (-0.91 points, p = 0.25) is not statistically significant on 3 rows; the
false-positive change is (p = 2.98e-08 on held-out). The two halves point the same way. The exception
does not touch `xss.*`, `cmd.*` or any other family in the `Referer`.

## What this does not show

- It is measured on one corpus, in which benign `Referer` headers were recorded with SQL-looking
  search URLs; the corpus's malicious test-application rows carry the previous attack URL in the
  `Referer`. A different deployment can have a different ratio, in either direction.
- It is library mode only. The serve path (chains, bans) was checked for no-change, not measured with
  the exception on.
- The 4-row recall cost is a count, not an estimate for other traffic.

## Serve smoke test

A throwaway upstream (`py -I -X utf8 -m http.server 18081`, started in an empty scratch directory) and
`venusflytrap serve --bind 127.0.0.1:18080 --upstream http://127.0.0.1:18081 --exceptions <file> --audit
smoke.jsonl --ocsf smoke-ocsf.jsonl --monitor-only`. The scratch file held the Referer entry plus a
`skip-inspection` entry (`skip-sig`) on `header x-signature` under `/hooks`. `exceptions check` listed
both as live (`skip-sig` with `-` for constructs).

- stderr at startup: one line, `warning: exception skip-sig skips inspection of header:x-signature under
  /hooks until 2027-10-30`, then the listening line.
- Three requests with `curl`: a GET with a SQL-looking `Referer`, a POST to `/hooks/x` with an
  `X-Signature` header holding SQL-looking text, and a plain GET.

| Request | JSONL `exceptions` | JSONL `skipped` | verdict, score | OCSF 4002 `unmapped.vft` |
|---|---|---|---|---|
| GET with SQL-looking `Referer` | `["referer-sql"]` | `[]` | Allow, 0 | `{"exceptions": ["referer-sql"], "skipped_fields": []}` |
| POST `/hooks/x`, `X-Signature` | `["skip-sig"]` | `["header:x-signature"]` | Allow, 0 | `{"exceptions": ["skip-sig"], "skipped_fields": ["header:x-signature"]}` |
| plain GET | `[]` | `[]` | Allow, 0 | absent |

- 3 audit lines and 3 OCSF lines (all HTTP Activity, class 4002; nothing was a Challenge or Block, so no
  2004). The `skipped` list holds the field; the exception that skipped it is the entry in `exceptions`
  (`skip-sig`).
- The empty upstream answered 404 (GET) and 501 (POST); the proxy forwarded all three.
- Both background processes were stopped afterwards (no listener remained on 18080 or 18081).

## Which commit each check ran on

Everything ran on `70632be` (the working tree held only the new example file and, later, this note and
two doc edits). The example file's `reason` text was changed before the A/B runs, and it does not feed
a verdict.

The default configuration stays exception-free; shipping this exception by default is the owner's decision.
