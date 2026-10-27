# DQ1 execution ledger

Subagent-driven execution of [the DQ1 plan](2026-10-28-dq1-measurement-foundation.md): one implementer and one task review per task, then a whole-branch review. The lines below are the working ledger, verbatim.

```
# SDD ledger — plan: docs/superpowers/plans/2026-10-28-dq1-measurement-foundation.md
Task 1: complete (commit a53faa9, controller review clean: index/worktree LF, baseline 288/278/32941/368 at 33,875 samples both models, gate self-check identical)
Task 2: minor (deferred): legend line also starts with "mcnemar" (match on column); CLI p-value tests all p=1 (.4g format of non-trivial p untested); untested: mixed serve_verdict presence, --intersect with zero shared rows, bench CSVs with diffs; unknown flag treated as a path
Task 2: complete (commit fe0826e, review clean)
Task 3: complete (commit 2ef6ee7, controller review clean: Wilson formula and reference values verified; library recall_ci95 [0.40151,0.47725], fp_rate_ci95 [0.007444,0.009407])
Task 4: minor (deferred): only `field` goes through csv_cell (rel/constructs raw, pre-existing); clusters.py short row/csv.Error traceback instead of exit 2; --top accepts negatives; field empty for NoEvidence misses (top contribution's own field would help the 148-row cmd.shell-meta group — DQ2 follow-up); Rust CSV test splits on ','
Task 4: complete (commit 79eda97, review clean; reviewer verified on dev rows: 180 misses, 148 cmd.shell-meta are NoEvidence scoring 28-39 < monitor_at 40, top always ∈ constructs)
Task 5: minor (deferred): shield.rs:363-371 build norm_opts.disabled from shield.disabled only (drops reliance on D2 decoder rejection); equivalence test lacks limit.payload-truncated and multi-id shadow list; shield.rs:419 doc that returned work covers judging pass only (second pass ≤ 2× work, own cap); [Task 6 handles: constructs column lists non-shadow only, promotion counts requests]
Task 5: complete (commit b73e1aa, review clean (opus): no leak from second pass, second pass only when shadow non-empty, real shadow-vs-disabled equivalence test)
Task 6: minor (deferred): library latency sampled after shadow/promo bookkeeping (p50/p95/p99 include it); tests lack benign-already-blocked, benign Monitor, promote==true, multi-id shadow column; shadow_hits computed every row; or_insert_with fallback would mask an id not in cfg.shield.shadow; duplicate --shadow ids not deduped (harmless)
Task 6: complete (commit 61d4513, review clean; classification arithmetic hand-checked)
Task 7: minor (deferred): replay stand-in upstream closes on Transfer-Encoding requests (would show as io mismatch; 0 seen in full run); head buffer unbounded (test stand-in only)
Task 7: complete (commit 8aef23d, controller review clean; full-corpus tcp: 33,711 replayed, 0 mismatches of any kind, upstream_5xx 0, io 0, 91 s; Cargo.lock unchanged)
Task 8: minor (deferred): dump BufWriter not flushed on mid-loop error; baselines.py open() without encoding (run with -X utf8); tests lack non-ASCII header and --mode serve dump; write error aborts after dump before score
Task 8: complete (commit c3ee2fa, review clean; schema compatible with baselines.py: query/headers/cookies as [k,v] lists, no cookie header in headers, 33,875 rows)
Task 9: minor (deferred): proxy_rejected example rels listed without checking dev/held-out side (paths only, payloads not opened)
Task 9: complete (commit 51744f4 + controller fix 18733a1 explaining incidental cmd.shell-meta miss cluster; review by controller)
Final review (opus): Ready with fixes — 0 Critical / 1 Important (RESULTS-DQ1 TCP and baseline-CI figures not traceable to saved outputs) / 8 Minor; no deferred minor must-fix
Final fix wave (controller): re-ran full TCP replay 3x at 18733a1 with saved status files (one run: 1 io mismatch, a 413 timing race on one oversized-body sample; others 0); saved baselines-wilson.txt; fixed cmd.shell-meta citation; spec 3.4/3.5 as-built notes
Carry forward: csv-quote rel/constructs before DQ5 corpora; NoEvidence rows need the top contribution's field (DQ2 first item); 413 race: client could read the reply before RST (half-close) — harness follow-up
```
