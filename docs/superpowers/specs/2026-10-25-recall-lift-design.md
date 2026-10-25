# Venusflytrap recall lift — design

*Date: 2026-10-25 · Status: draft for review · Scope: roadmap item 1 (lift real recall). Approved section by section in the design session; this document records the result. Implementation follows in a separate plan.*

## 1. Goal

Raise the engine's recall on real traffic without giving up the two properties that make it worth having: a low false-positive rate and mutation robustness. Every gain is measured on data the rules were not written from.

Concretely:

- inspect request bodies as structured fields instead of one opaque string;
- decode the escape and encoding forms that hide real attacks;
- close the truncation and decoding paths that let attacks through unseen (fail open);
- add detection constructs for the attack classes that dominate the measured misses;
- make every construct and decoder individually switchable, so each one's worth is measured, not assumed.

## 2. Non-goals

- Production baselines (ModSecurity v3 + CRS, SafeLine): roadmap item 2.
- A second labeled corpus: roadmap item 3. Until then the held-out half of blazehttp stands in, with the caveats in §10.
- Guided adversarial search (WAF-A-MoLE): roadmap item 4. Mutation robustness for the new families is not measured here because `eval/mutate.py` only seeds SQLi and XSS.
- Proxy hardening, the kill chain, bans, the admin API and console: owned by the operable-service program (SP1–SP7). This design only provides the interfaces in §9.
- Parser-differential (WAFFLED-style) evaluation. Body parsing fails closed (§5), but a differential test harness is out of scope.
- Changes to `eval/parse_corpus.py`, `eval/baselines.py`, `eval/mutate.py` or `crates/vft-cli/examples/bench_http.rs` beyond the one clippy line already applied. They are the owner's harness and stay comparable to the published numbers.

## 3. Starting point (measured, 2026-10-25)

All numbers are from the library path (`Shield::inspect`), release build, on this machine.

**Full blazehttp corpus (33,877 requests: 658 malicious, 33,219 benign):**

| Engine | TP | FP | FN | Recall | Precision | F1 | FP rate |
|---|---|---|---|---|---|---|---|
| regex-signature | 127 | 126 | 531 | 19.3% | 50.2% | 0.279 | 0.38% |
| libinjection | 214 | 93 | 444 | 32.5% | 69.7% | 0.444 | 0.28% |
| Venusflytrap, commit `b010a01` | 284 | 542 | 374 | 43.2% | 34.4% | 0.383 | 1.63% |
| Venusflytrap + command-position `$(` fix | 282 | 268 | 376 | 42.9% | 51.3% | 0.467 | 0.81% |

**Mutation robustness (22 seeds → 660 mutants), unchanged by the `$(` fix:** Venusflytrap 86.4% → 83.0% (96% retained); libinjection 90.9% → 52.1% (57%); regex 63.6% → 34.2% (54%).

**Prototype of the §4.1 split** (current tree with the `$(` fix; provisional until M0 re-measures on SP1's tip):

| Half | Malicious | Benign | Recall | FP rate |
|---|---|---|---|---|
| dev | 329 | 16,610 | 44.4% | 0.85% |
| held-out | 329 | 16,609 | 41.3% | 0.76% |

**What the misses are.** A heuristic content classifier over the 183 dev misses (first match wins; approximate):

| Class | Dev misses |
|---|---|
| Unclassified, mostly JS obfuscation (concatenated or octal bracket keys, JSFuck) | 54 |
| XSS tag or attribute forms not modeled | 40 |
| Code injection / JS-context calls | 31 |
| SQLi variants | 21 |
| XXE | 11 |
| Deserialization, incl. OGNL/Struts | 11 |
| Other: recon 5, SSRF 3, SSTI 2, JNDI 2, command injection 2, path 1 | 15 |

23 dev misses need base64 decoded inside a single field; several of those decode to JSON full of `\u00XX` escapes. Only 6 dev misses carry `\u00XX` in the raw request, so nested `\u`-escaped JSON matters only underneath base64.

**Findings that shaped the design:**

- The `$(` false positives were backticks, not jQuery: 272 of the 274 FPs the fix removed contain a backtick, and 245 are binary bodies where a stray 0x60 byte reads as one.
- Latent `cmd.shell-meta` fires on the `;` in 33,855 of 33,877 User-Agent headers. It is background noise, not a partial detection.
- 506 of 658 attacks have an empty body. Body work can reach at most 152 attacks.
- 1,321 benign bodies are protobuf, of which only 355 exceed 20% non-printable bytes, and 1,380 benign `text/plain` bodies are JSON. Body handling must use Content-Type and content sniffing, not a byte ratio alone.
- A code review (2026-10-25) confirmed by probe:
  - **H1** one invalid UTF-8 percent sequence (`%ff`) disables URL decoding for the whole field;
  - **L5** `+` becomes a space before base64 detection;
  - **C2** tokens past 4,096 are dropped silently and `graph_truncated` is never read;
  - **C3** fields past 64 KiB are truncated silently.

## 4. Evaluation and gates

### 4.1 Split

`eval/split.py` makes a fixed, label-stratified 50/50 split of blazehttp:

- key: SHA-256 of each raw `.white`/`.black` file;
- within each label, files are sorted by key; the first half (rounded up) is dev, the rest held-out;
- byte-identical files share a key, so duplicates stay on one side (7 such files exist);
- no randomness, no dependence on paths.

It walks the corpus in the same `os.walk` order as `parse_corpus.py`, pairs each raw file with its JSONL line, and checks every label. Outputs: `manifest.tsv` (relative path, label, SHA-256, side) for raw-file harnesses, and `dev.jsonl` / `heldout.jsonl` for the JSONL harness.

### 4.2 Discipline

- Rules, decoders and tests are written from **dev** misses only. Held-out misses are never opened.
- Held-out is scored once per milestone, at its end, and reported as measured. It is never tuned on.
- Contamination log: before the split existed, about 30 example payloads from the full corpus were read while sizing the misses (2026-10-25). Some are in the held-out half. The escape forms chosen partly because of them (`\u{…}`, octal, `&tab;`) are standard documented evasions, not corpus-specific tricks.

### 4.3 Ablation

Leave-one-out on dev: one baseline run with everything enabled, then one run per registered construct or decoder with only that one disabled through `shield.disabled`. Each row reports ΔTP, ΔFP and pass/fail. Constructs and decoders that predate this work are reported too, but the drop rule applies only to new and changed ones (§4.4). The ablation runs where the eval lives at M0: as `--manifest … --side dev --disable <id>` on SP1's `vft-cli eval` if that has landed, otherwise as a new example `crates/vft-cli/examples/ablate_http.rs`.

### 4.4 Gates (every milestone)

| Gate | Threshold |
|---|---|
| `cargo test --workspace`, `cargo clippy --all-targets -- -D warnings` | green |
| Dev FP rate | ≤ 1.0% |
| Each new detection construct or decoder (leave-one-out on dev) | ΔTP > ΔFP, else dropped |
| Each widened or fixed construct or decoder (`xss.dangerous-proto`, the binary list, `decode.b64-whole`) | the change alone, new vs previous behavior on dev: ΔTP > ΔFP, else reverted |
| Each limit or bypass fix (`decode.percent-lossy`, owner ruling 2026-10-25) | adds 0 dev FPs, and its probe regression test blocks |
| Each fail-closed inspection fix (C2 windowing, C3 chunking; owner ruling 2026-10-25) | its probe regression test blocks; FPs from newly inspected text count against the dev FP ceiling (≤ 1.0%) |
| Mutation robustness | retained ≥ 96%, and mutant recall ≥ 83.0% |
| Full-corpus latency | p95 < 1 ms (PRD NFR1) |
| Held-out | scored once at milestone end; reported, never tuned on |

### 4.5 Reporting

Per milestone: confusion matrices for dev, held-out and full corpus; seeds and mutants; the ablation table; p50/p95/p99 latency. Every number goes into `eval/RESULTS-RECALL.md` and the Claude Doc (§8).

## 5. Body structuring

New module `vft-core/src/body.rs`: `body_fields(content_type, body) -> Vec<Field>`. `Request::fields()` calls it instead of emitting one `<body>` field. Query, header and cookie handling are unchanged.

| Body kind | Detected by | Becomes |
|---|---|---|
| Form | `application/x-www-form-urlencoded`, or a `k=v&…` sniff | one field per parameter: `form:<name>` |
| JSON | Content-Type containing `json`, or a body starting with `{`/`[` that parses | one field per string leaf: `json:<JSON-Pointer>`; keys become fields only if they contain non-identifier characters |
| Multipart | `multipart/*` with a boundary | each part split by its own Content-Type (one level): `multipart:<part>`; the `filename` value is its own field |
| XML | Content-Type containing `xml`, or a body starting with `<?xml` / `<!DOCTYPE` | kept whole: `xml:/` |
| Binary | Content-Type `protobuf`, `octet-stream`, `image/*`, `audio/*`, `video/*`, `zip`, `gzip`; or > 20% non-printable bytes | no text field |
| Anything else, or a parse failure | — | today's single `<body>` field, plus informational `limit.body-unparsed` |

- JSON leaves come out of `serde_json` already unescaped.
- A form value or JSON leaf that is itself JSON is expanded once more; total depth ≤ 2. JSON nesting stops at 32 levels.
- At most 256 fields per body; any further content is joined into one remainder field, never dropped.
- Inspection budget: oversized fields are inspected in 64 KiB chunks up to `shield.max_inspect_bytes` (4 MiB) per request. Past the budget, `limit.payload-truncated` hard-blocks the request (fixes C3).
- Field names now carry real parameter names, so `ApiSafetyDetector` (which keys off `id`, `*_id`) will fire more often. Its effect is measured by ablation.

## 6. Normalizer

Every decoder has a stable id and can be disabled.

**Fixes:**

| Id | Change |
|---|---|
| `decode.percent-lossy` | Public `normalize::percent_decode_lossy`: decodes percent sequences byte by byte with lossy UTF-8, so one bad byte no longer disables the layer (fixes H1). SP1's `canonical_path` reuses it. |
| `decode.b64-whole` | Today's whole-field base64 decoder, now with an id. It, and `decode.b64-island`, also run on the text before `+` → space (fixes L5). |

Today's other decoders also get ids so they can be ablated: `decode.entity` (HTML entities) and `decode.esc-hex` (`\xNN`, `\uNNNN`). `decode.percent-lossy` replaces today's URL decoder.

**New decoders:**

| Id | Decodes | Guard |
|---|---|---|
| `decode.esc-es6` | `\u{61}` … `\u{10FFFF}` | 1–6 hex digits, a valid scalar value |
| `decode.esc-octal` | `\141` | exactly 3 digits, first 0–3, result ≥ 0x20 |
| `decode.ent-html5` | `&tab;` `&newline;` `&colon;` `&bsol;` `&lpar;` `&rpar;` `&equals;` `&grave;` `&lsqb;` `&rsqb;` `&lcub;` `&rcub;` `&excl;` `&quest;` `&period;` `&comma;` `&dollar;` `&percnt;` `&num;` | fixed table, case-sensitive like browsers |
| `decode.ent-loose` | numeric entities without `;` (`&#106avascript`) and with long zero padding | numeric only; ≤ 10 digits |
| `decode.b64-island` | a run of ≥ 16 base64 or base64url characters inside a field | valid UTF-8, ≥ 90% printable, and contains a structural character (`< > ( ) { } ' " ; $ \|`) |

- Base64 islands become **derived fields** (`Normalized.derived: Vec<String>`), analyzed by `Shield` as extra fields named `<field>#b64`. Splicing decoded text into the original would let tokens combine across the seam. At most 8 islands per field; derived fields are checked for further islands once (depth 2).
- JS string concatenation and whitespace inside URL schemes are handled in the sinks (§7.3), not here, because they are context semantics, not generic decoding.

## 7. Sink registry and constructs

### 7.1 Layout

- `graph/mod.rs`: `analyze()`, `Analysis`, token windowing.
- `graph/tokenize.rs`: unchanged, except the M4 keyword step.
- `graph/sinks/mod.rs`: the registry. Family files: `sql.rs`, `xss.rs`, `js.rs`, `shell.rs`, `path.rs`, `xxe.rs`, `ssrf.rs`, `deser.rs`, `expr.rs`.
- Sinks stay plain functions: `fn detect(cx: &SinkCtx, hits: &mut Hits)`.

### 7.2 Registry

```rust
pub enum ConstructKind { Sink, Latent, Signature, Decoder, Limit }
pub struct ConstructInfo {
    pub id: &'static str,          // dotted, stable: "sqli.union-select"
    pub family: Option<Family>,    // None for decoders
    pub kind: ConstructKind,
    pub summary: &'static str,
}
pub fn constructs() -> &'static [ConstructInfo];
```

- Each construct is a `static ConstructInfo`; the registry slice references the statics. `Hits::reach(&'static ConstructInfo)` and `Hits::latent(...)` take the static, not a string, so an unregistered id cannot be emitted and `Pattern.name == id` holds by construction. `Hits` drops disabled constructs.
- All patterns get dotted ids, including today's: `sqli.union-select`, `sqli.boolean-tautology`, `sqli.quote-breakout`, `sqli.stacked-query`, latent `sqli.sql-keyword`; `xss.script-tag`, `xss.event-handler`, `xss.dangerous-proto`, `xss.tag-with-handler`, latent `xss.html-tag`; `cmd.cmd-substitution`, `cmd.chained-command`, latent `cmd.shell-meta`; `path.directory-traversal`, latent `path.dotdot-segment`; `sig.*` for signature hits; `api.type-violation`; `recon.sensitive-path-probe`.
- Ids are never reused. A rename adds an alias.
- `shield.disabled: Vec<String>`. An id not in `constructs()` is a configuration error.

### 7.3 Fail-closed limits

| Construct | Option key | Fires when | Evidence |
|---|---|---|---|
| `limit.payload-truncated` | `shield.max_inspect_bytes` (new, 4 MiB) | a request exceeds the inspection budget (each field charged once), or a piece is still cut after lossless recursive splitting reaches its depth bound, or the per-request normalization work cap `shield.max_normalize_work` (default 2 × max_inspect_bytes) is reached | hard Block (owner ruling 2026-10-26) |
| `limit.graph-truncated` | `shield.max_graph_windows` (new, 32) | a field needs more 4,096-token windows than the cap | Suspicious |
| `limit.body-unparsed` | `shield.body_parse` | a body falls back to one whole field | informational, weight 0 |

Long token streams are analyzed in 4,096-token windows overlapping by 64 tokens, with patterns de-duplicated across windows (fixes C2). Text-level checks always see the whole field. 32 windows cover a full 64 KiB field, so `limit.graph-truncated` should not fire on default caps; it is defined and tested in case the caps change.

### 7.4 New constructs

Each is written from dev misses only (the plan's appendix lists the motivating dev requests per construct) and must pass leave-one-out (§4.4). **Reachable** blocks on its own; **latent** is a weak signal.

| File | Construct | Reachable when | Guard / note |
|---|---|---|---|
| `js.rs` | `js.sink-call` | `alert/prompt/confirm/eval/Function/setTimeout/atob/fetch/document.write` is called after a JS breakout (`';` `";` `</script>`), or is reached through a global (`window/top/parent/self/this/frames`) | bracket keys resolved by joining literal pieces (`'ale'+'rt'`, `'ale' 'rt'`) after §6 escape decoding |
| | `js.global-bracket-call` | `window['…'](`: bracket access on a global, immediately called | |
| | `js.jsfuck` | ≥ 40 characters, ≥ 95% from `[]()!+` | |
| `xss.rs` | `xss.dangerous-proto` (widened) | scheme check ignores tab/CR/LF inside the scheme; adds `vbscript:` and `data:image/svg+xml` | browsers strip exactly those characters |
| | `xss.active-tag` | `<object` with text/html, `<embed src`, `<iframe srcdoc`, `<meta http-equiv=refresh`, `<base href`, `<form action=javascript`, `<link rel=import`, SVG/MathML `href` to script | |
| `sql.rs` | `sqli.time-delay` | a call to `sleep(` `pg_sleep(` `benchmark(` `dbms_pipe.receive_message(`, or `waitfor delay '` | promoted from today's latent text match |
| | `sqli.quote-concat` | a quote, then `\|\|` or `+`, then a SQL function call or `(select` | |
| | `sqli.case-when` | `case … when … then … end`, in order | |
| | `sqli.select-from` | the value starts with `select`, then `*`, a column list or a function, then `from <identifier>` | prose risk ("select a size from the menu"); ablation decides |
| | `sqli.error-based` | `cast(… as`, `convert(`, `extractvalue(`, `updatexml(`, `to_char(1/0)` with `select` or a quote breakout | |
| `shell.rs` | binary list (affects `cmd.chained-command`, `cmd.cmd-substitution`) | adds `touch, echo, sleep, dig, ifconfig, ipconfig, netstat, ps, printf, base64, head, tail, grep, find, cp, mv, mkdir, powershell, cmd, certutil, php, ruby, node, busybox, ncat, socat, telnet` | recovers the 2 TPs the `$(` fix lost; gated as one change |
| `xxe.rs` | `xxe.external-entity` | `<!DOCTYPE … [` with `<!ENTITY … SYSTEM/PUBLIC`, or a parameter entity `<!ENTITY %` | |
| | `xxe.xinclude` | `xi:include`, or an `xmlns:xi` declaration with an `href` | |
| `ssrf.rs` | `ssrf.dangerous-scheme` | the value is a URL with `gopher/dict/file/ldap/tftp/jar/netdoc` | never in Header fields |
| | `ssrf.internal-host` | the value is an http(s) URL to loopback or a metadata address (`127/8`, `localhost`, `::1`, `0.0.0.0`, `169.254.169.254`, decimal/hex forms such as `2130706433`, `0x7f000001`) | RFC 1918 hosts are latent only |
| `deser.rs` | `deser.java-serialized` | the value starts with `rO0AB` or `aced0005` | magic checked on the base64 text |
| | `deser.php-object` | `O:<n>:"Class":<n>:{` | bare `s:`/`a:` structures latent |
| | `deser.java-xmldecoder` | `<java` with `<object class=` or `<void method=` | |
| | `deser.type-gadget` | `"@type":"a.b.C"`, `"$type":"System.…"`, `!!python/object`, `!!javax.script`, `ObjectDataProvider` | |
| `expr.rs` | `expr.template` | `{{ }}`, `${ }`, `#{ }`, `<%= %>`, `{% %}` containing arithmetic on numbers (`7*7`) or `__class__` / `__globals__` / `.getClass(` | |
| | `expr.ognl` | `%{(#`, `#_memberaccess`, `#context[`, or static access `@pkg.Class@method` | |
| | `expr.spel` | `T(java.lang.…)` | |
| | `expr.jndi` | `${jndi:` after removing `${lower:x}`, `${upper:x}`, `${::-x}` obfuscation | |

- New `Family` variants: `Xxe`, `Ssrf`, `Deserialization`, `ExpressionInjection` (additive, in `judgment.rs`).
- **Tokenizer step (M4):** `case, when, then, else, end, cast, waitfor` become SQL keywords. That changes token kinds existing sinks read, so the step is diffed against the previous milestone on its own before any new SQL construct is gated.
- No recall target is promised. Even if every construct passed, most of the 54 unclassified misses and the long tail would remain.

## 8. Milestones

Work happens on branch `recall-lift` in its own worktree (`../venusflytrap-recall`), cut from SP1's branch tip once SP1 lands. Every milestone ends with a commit the owner approves first. Nothing is pushed and nothing touches `main` without explicit approval.

| # | Milestone | Must show |
|---|---|---|
| M0 | Baseline: commit `eval/` scripts, `split.py` + manifest, the ablation harness; replace the synthetic numbers in `README.md` and `docs/BENCHMARK.md` with measured ones | dev / held-out / full / seeds / mutants on SP1's tip: the reference |
| M1 | Registry refactor: `graph/sinks/`, dotted ids, `shield.disabled` + validation | `label,pred,score` identical to M0 for all 33,877 + 22 + 660 requests |
| M2a | Fail-closed and decoder fixes: `percent_decode_lossy` (H1), base64 before `+` → space (L5), windowing (C2), chunking + `limit.*` (C3) | the probe regression tests block; FP and latency re-measured |
| M2b | `body.rs` and the §6 decoders | per-decoder ablation |
| M3 | XSS and JS constructs | per-construct ablation; robustness gate |
| M4 | Tokenizer keyword step (diffed alone), then SQLi constructs and the binary list | as M3 |
| M5 | XXE, SSRF, deserialization, expression injection | as M3 |

**Claude Doc** (doc `c555ba6b-ff38-4ea4-875c-3b4f08f0c8fe`), updated once per milestone:

- Results: the main table becomes milestone rows (dev / held-out / full) with confusion counts; the robustness table is re-run.
- Methodology: the split, the contamination log and the eval-vs-proxy caveats.
- A new "Ablations" tab for the per-construct tables.
- Error analysis: re-run on dev misses only.

## 9. Interfaces with the operable-service program (SP1)

Owned here, consumed by SP1 (refines operable-service-design §7):

1. `graph::sinks::constructs()` and `ConstructInfo` as in §7.2. `kind` and `Option<Family>` are additive to SP1's `{ id, family, summary }`.
2. `limit.payload-truncated`, `limit.graph-truncated`, `limit.body-unparsed` with the option keys in §7.3.
3. Body field names `form:<name>`, `json:<JSON-Pointer>`, `multipart:<part>`, `xml:/`.
4. `normalize::percent_decode_lossy`.
5. `shield.disabled`: recall-lift lands second, so it adds the option descriptor and the `disabled ⊆ constructs()` check.
6. New `Family` variants (§7.4).

Shared files: `judgment.rs`, `config.rs`, `shield.rs`. SP1 lands first; recall-lift rebases onto it; SP1's re-measured library numbers are M0's baseline. These decisions are also recorded in the session notes (`recall-lift-interface-decisions.md`).

## 10. Threats to validity

- **Held-out is not a new corpus.** blazehttp contains template siblings (the same payload with different filler words, often base64-wrapped). A file-hash split can put siblings on both sides, so held-out overstates generalization. Roadmap item 3 is the real test.
- **Small halves.** 329 attacks per half: about ±2.7 points of recall noise per half. The prototype's 3-point dev/held-out gap is within it.
- **Contamination** (§4.2): about 30 full-corpus payloads were read before the split.
- **Eval vs proxy (M8):** `parse_corpus.py` drops the raw `Cookie` header the proxy inspects, decodes bodies as latin-1 where the proxy uses lossy UTF-8, and `bench_http` is stateless. Library numbers describe `Shield::inspect`, not the serve path; SP1 measures the serve path separately.
- **Robustness coverage:** mutation seeds cover SQLi and XSS only. New families have no robustness number until roadmap item 4.
- **Heuristic miss classes:** the class sizes in §3 come from a first-match regex classifier and are approximate. They size the work; they are not results.

## 11. Testing

- Per construct: positive cases from dev misses or public evasion forms, never from held-out; benign look-alike negatives for every guard named in §7.4 (prose "select … from", intranet URLs, JWTs, jQuery, Windows paths for octal).
- Probe regressions: `%ff`-appended SQLi in a form body; base64 containing `+`; 4,100 commas followed by an attack; an attack past 64 KiB; an attack past the 256-field body cap. All must block.
- Registry: no duplicate ids; every `shield.disabled` id resolves; an unknown id is a configuration error.
- Refactor equivalence: a script diffs `label,pred,score` between two builds; M1's diff must be empty.
- Property tests: extend `tests/fuzz_props.rs` to `body.rs` and the new decoders (random bodies and content types never panic and stay within bounds).
- Constraints throughout: `#![forbid(unsafe_code)]`; no `unwrap()`/`expect()` on attacker-reachable paths; `vft-core` stays I/O-free and deterministic.
