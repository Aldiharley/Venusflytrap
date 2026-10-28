# DQ4: external WAF baselines on byte-identical replays (plan)

Goal: score ModSecurity v3 + CRS 4.x and Coraza + CRS 4.x on the same requests, sent as the same
bytes, that Venusflytrap's TCP mode replays, and compare them like for like with Venusflytrap.
Detection code does not change.

1. **Images.** Pull `owasp/modsecurity-crs` (nginx, CRS 4.30.0) and the CRS project's Coraza image
   `ghcr.io/coreruleset/coraza-crs` (Caddy, CRS 4.30.0), each at an exact dated tag; record the digests.
   `ghcr.io/corazawaf/coraza-caddy` refuses anonymous pulls, so it is not used.
2. **Compose** (`eval/baselines/docker-compose.yml`): one stand-in upstream (the ModSecurity image's
   nginx binary with a tiny `return 200` config, no ModSecurity module), one ModSecurity and one
   Coraza service. Only the two WAF ports are published, on `127.0.0.1`; the upstream sits on an
   internal network. Paranoia level and inbound threshold come from environment variables.
3. **Replayer** (`eval/replay_external.py`, stdlib only). Port the TCP mode's skip and framing rules
   (`rewrite_for_replay`, `parse_raw`, `Sources::Distinct`) so every engine receives the bytes
   Venusflytrap's TCP mode sends. Zero-linger client sockets, one connection per request. Three
   outcomes per row: `blocked` (403), `passed` (200), `failed` (anything else, or an I/O error).
   CSV `rel,label,verdict,status` plus a JSON summary with Wilson intervals and a digest of the sent
   bytes. A stand-in upstream subcommand serves Venusflytrap's own proxy. Unit tests run against
   local socket stand-ins (`eval/test_replay_external.py`).
4. **Runs.** CRS PL1-4 at threshold 5, and PL1/PL2 at 10 and 20, on both engines (blocking mode,
   JSON audit log captured for rule IDs). Venusflytrap: `venusflytrap serve` behind the same
   replayer, plus `eval --mode library --out` (per-row reference) and `eval --mode tcp` (counts).
5. **Report** (`eval/dq4_report.py`): TP/FP/TN/FN, recall and FP rate with Wilson 95 % CIs per
   engine and setting, TPR at the CRS setting nearest Venusflytrap's FP rate, exact McNemar against
   Venusflytrap's per-row verdicts on shared rows, CRS FP rule-family counts. Results in
   `eval/RESULTS-DQ4.md`; one status line in `docs/BENCHMARK.md`. Run outputs stay in the
   git-ignored `.superpowers/dq4/`.
