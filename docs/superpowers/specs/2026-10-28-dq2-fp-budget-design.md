# DQ2 — Buy back the false-positive budget (design)

*Date: 2026-10-28 · Status: draft for review, owner-delegated (the owner accepted all detection-quality recommendations on 2026-10-27) · Builds on: DQ1 (Wilson CIs, McNemar, `clusters.py`, `field`/`cause`/`top`/`shadow` CSV columns, `shield.shadow`, `--promotion`) and SP2 (options registry, `decided_by`) · Research: `reports/Raising WAF recall and baselines.md` (local, not committed), phase 1 minus shadow mode.*

## 1. Goal

Lower the dev false-positive rate from 147 / 16,610 (0.89%, merged recall-lift + SP1 tip) to **≤ ~0.6% with dev ΔTP ≥ 0**. To do that, the engine has to read each field under the grammar its consumer uses. Every change is tuned on dev rows only. Held-out is scored once, at the end. This phase changes decisions on purpose, so the SP2 identity gate becomes an attribution check (§6.3).

The target comes from the research and is not a projection. One fact sizes it: the leave-one-out on dev puts 114 of the 147 dev FPs on the four sinks DQ2 changes (§3).

## 2. Non-goals

- New attack families or recall constructs: XSS/JS tokenizer, base64 islands, XXE, deserialization, SSRF/SSTI. They belong to DQ3+.
- SQLi variant nodes (time-delay, CASE, error-based).
- gzip decompression, and any new crate.
- Changing `scoring.*` thresholds or weights.
- External baselines (DQ4) and new corpora (DQ5).
- Changing the dev/held-out manifest.

## 3. What the dev FPs actually are (evidence for the design)

I attributed the 147 dev FP rows (label 0, Challenge/Block in `venusflytrap-recall-runs/merged/lib_dev.csv`) to fields by reading dev raw files only:

| Construct | Dev FP rows | Where and what |
|---|---|---|
| `cmd.chained-command` | 37 | **All 37** are `&id=`: a URL query separator followed by the parameter name `id`. 25 sit in a query value carrying JSON with an embedded URL, 7 in form bodies (one `<body>` field today), 4 in Referer, 1 in protobuf. |
| `sqli.union-select` | 40 | People searching *about* SQL ("site:segmentfault.com union select 关键字怎么用"): 25 in Referer, 12 in query values, 2 in protobuf; plus 2 English prose rows. |
| `sqli.boolean-tautology` | 28 | A search about SQLi ("sql注入的“and 1=1，and 1=2”测试法…"): 18 in Referer, 5 in query; 4 large telemetry bodies; 1 prose row ("1 and 1=1 is a very basic …"). |
| `sqli.stacked-query` | 12 (9 unique) | Large JSON/form telemetry bodies. The sink arms on any `;` and fires on a DML keyword *anywhere later* in the window (`sql.rs`, `semi` is never reset). |
| `cmd.shell-meta` (latent) | present on all 147 | Leave-one-out d_fp = **0**. It adds score and corroboration but decides no FP. |

UA/Accept `;` therefore drives no current FP. The FP-heavy sinks fire on prose, on URL separators and on unsplit bodies. Header grammars matter for score hygiene and as a guard for later constructs (§4.1). The FP budget comes from §4.2–§4.3.

## 4. Components

### 4.1 Per-header grammar matrix: deferred to DQ3 (D15)

The evidence in section 3 shows that a grammatical `;` in User-Agent, Accept or `sec-ch-ua` decides no dev FP: `cmd.shell-meta` has a leave-one-out d_fp of 0. Its only measurable effect would be to lower background scores. That includes the malicious rows that today sit just below `monitor_at` (DQ1 found 148 dev misses scoring 28 to 39 with `cmd.shell-meta` on top). DQ2 therefore leaves headers as they are. The grammar design below is kept as the starting point for DQ3, where header-borne constructs need it as a guard. These are its notes:

- Grammars `parse.header-product` (User-Agent: products `tok[/tok]` and comments `( … )`, nested one level, with no quote, backslash, backtick, `$`, `|`, `&`, `<`, `>` or brace), `parse.header-list` (Accept*, Content-Type: `item(;k=v)*` separated by `,`) and `parse.header-sf-list` (`sec-ch-ua*`).
- When a value parses fully, its grammatical `;`/`,` are separators. Otherwise the header is inspected as today, so Shellshock keeps full force.
- On dev, 100% of benign UA, Accept-Language and Accept-Encoding values parse, as do all 15,497 benign Accept values.

### 4.2 Body classification (finish recall-lift M2b)

**What exists.** No `body.rs`. The whole body becomes one `<body>` field via `String::from_utf8_lossy`. Binary bytes become U+FFFD, and 245 earlier binary FPs were removed only indirectly, by requiring a binary after a backtick (`shell.rs`). `serde_json` is already a vft-core dependency. No decompressor is in `Cargo.lock`. Dev benign bodies by declared type: JSON 1,803; text/plain 1,057 (696 of them are JSON); form 803; protobuf 688 (89 of them gzip by magic); multipart 89; ndjson 25 (22 gzip). Dev malicious bodies are form 44, multipart 13, untyped 11, JSON 6 and XML 3, with **no protobuf or gzip**.

**Change.** New `vft-core/src/body.rs`: `body_fields(content_type: Option<&str>, body: &[u8]) -> Vec<Field>`. `Request::fields()` calls it in place of the single `<body>` push.

| Class | Decided by | Becomes |
|---|---|---|
| gzip/zlib/zip/PNG/JPEG/GIF/PDF | magic bytes, whatever the declared type | no text field |
| Declared binary (`protobuf`, `octet-stream`, `image/*`, `audio/*`, `video/*`) | Content-Type **and** the bytes look binary: a C0 control other than TAB/LF/CR, or invalid UTF-8 | no text field |
| Declared binary but all printable valid UTF-8 | — | inspected as text. A content-type label alone never hides a payload (parser-discrepancy guard). |
| JSON | Content-Type contains `json`, or a body starting with `{`/`[` that parses (covers text/plain JSON); ndjson line by line | one field per string leaf, `json:<JSON-Pointer>`. Keys become fields only if they contain non-identifier characters. A leaf that is itself JSON is expanded once (depth ≤ 2). Nesting stops at 32. |
| Form | `application/x-www-form-urlencoded` | `form:<name>` per value and `form-key:<name>` per key, split on raw `&` before any decoding |
| Multipart | `multipart/*` with a boundary, one level | each part is classified by its own Content-Type with this same table; `filename` is its own field |
| XML, other, or a parse failure | — | today's single `<body>` field (XML kept whole) |

- **Caps.** At most 256 fields per body. The remainder is joined into one `json:#rest` field and never dropped. The existing chunking and byte budget (`shield.max_inspect_bytes`) apply per field.
- **UTF-8.** Valid non-ASCII UTF-8 is neutral. Nothing in the engine scores it today, and `count_scripts` counts only Latin/Cyrillic/Greek mixing. Invalid UTF-8 in a *text-class* body is anomalous and emits a new Suspicious limit `limit.body-non-utf8` (0.6, `weight_api`), mirroring `limit.header-non-utf8`. Overlong encodings are invalid UTF-8 under Rust's decoder, so they fall into the same case. Binary-class bodies do not emit it.
- **API safety.** `ApiSafetyDetector` matches `id`/`*_id`/`page`/`count` on the last name segment, so `form:id` and `json:/user/id` still qualify. This is a deliberate widening, measured with the change.
- **Registry.** Decoder-kind ids `parse.body-binary`, `parse.body-json`, `parse.body-form`, `parse.body-multipart`; disabling one falls back to `<body>` for that class. The limit `limit.body-non-utf8` is new.
- **Measured by.** A/B per id, dev only. The binary class is measured on its own because it is the change most likely to cost recall in principle (0 malicious dev bodies are affected). Field names show up in DQ1's `field` column, so `clusters.py` attributes every move.

### 4.3 SQL parse-validity gate

**What exists.** `sql.rs` matches token patterns inside one 4,096-token window. The tautology check accepts `x = x` when *any* quote appears anywhere in the window. `stacked-query` accepts a `;` and a DML keyword arbitrarily far apart. The tokenizer reads `1e1union` as one number token. The normalizer has already stripped `/* */`, `--` and whitespace-preceded `#` comments, and it keeps `/*! … */` content (`canonicalize_ws_comments`).

**Change.** New pure-Rust module `vft-core/src/graph/sqlgate.rs` (est. 450–600 lines with tests). It holds an error-tolerant SQL lexer plus a recursive-descent *fragment* parser.

- **Lexer.** It never fails; unknown characters become `Err` tokens. Tokens:
  - numbers: `1`, `1.5`, `.5`, `1e1`, `0x…`, with letters split off a number (`1e1union` → `1e1`, `union`);
  - strings `'…'` / `"…"` with `\` and doubled-quote escapes, and backtick identifiers;
  - ASCII identifiers (non-ASCII letters are `Err`; D6);
  - `@v` / `@@v`;
  - operators `= <=> != <> < > <= >= + - * / % || && | & ^ !`, the keyword operators `and or xor not like rlike regexp is in between div mod`, and `( ) , ; .`
- **Three start states**, as libinjection does. Unquoted: the value begins in an expression position. After `'` or after `"`: everything up to the first unescaped matching quote is string content.
- **Fragment grammar.** `prefix := operand` (number, string, `null`, `@var`, function call, or `)` closing up to 3 outer parens; a bare identifier is not accepted as a prefix, D7). `prefix` is optional only before `union`. Then:
  - `cont := { binop operand | ')' }*`
  - then at most one dangerous node: `union [all|distinct] select list [from ref [where expr]] [group|order by …] [limit n[,n]]` → `sqli.union-select`; or `; stmt`, where `stmt` is `select…`, `insert into`, `update ident set`, `delete from`, `drop (table|database)`, `exec[ute] ident`, `create (table|user|…)`, `declare`, `waitfor delay`, or `shutdown` → `sqli.stacked-query`.
  - A tautology is a `binop ∈ {or, and, xor, ||, &&}` followed by a comparison whose sides are equal literals (`1=1`, `'a'='a'`, `2 like 2`) → `sqli.boolean-tautology`.
  - After the node the fragment must reach end of input. One tolerance applies: a trailing unterminated string in the start state's quote is accepted, because the host query's own closing quote completes it (`' or 'a'='a`).
- **Select list items** are numbers, strings, `null`, `*`, ASCII identifiers, `@@v`, function calls, subqueries or `0x…`.
- **Inputs.** The gate runs on the field's normalized `text`. When that text is a JSON object or array, it runs on each string leaf instead; this keeps `{"id":"1 and 1=1"}` under whole-field base64. For the path, it runs on each `/` segment (keeps `/api/products/123 and 1=1/reviews`).
- **Wiring.** `sql.rs` keeps its token checks as the *candidate* test. The three gated sinks then call `sqlgate::confirm(text, node) -> bool` and emit `reach` only on success. On failure they emit `latent(&SQL_KEYWORD)`, so the construct is still visible as a latent signal. `sqli.quote-breakout` is not gated in DQ2 (net +4 on dev; D9).
- **`cmd.chained-command` is shell, not SQL.** It gets a command-position rule in `shell.rs` instead (D8): the binary must be a whole shell word, followed by end of text, whitespace, or one of `; | & < > )` and backtick. It may not be followed by `=` (an assignment or URL parameter, which covers all 37 dev FPs), `(`, `.` or `:`. Because the rule works on text, as `substitution_runs_binary` already does, the command word may contain empty quote pairs and backslashes that the shell removes (`wh''oami`, `w\hoami`). That keeps a dev TP that only an accidental tautology hit catches today.
- **Registry.** Gate ids `gate.sqli-grammar` and `gate.cmd-position`, with a new `ConstructKind::Gate` (no family) and the registry test extended to cover it. Disabling a gate restores today's sink behaviour, so A/B runs need one build. Gates cannot be shadowed. Shadow mode is for *new* constructs; these are changed existing ones (A/B).
- **Sizing and DQ3 deferrals.** Deferred to DQ3 (SQLi variants on this parser): time-delay and `CASE` nodes, error-based functions, comparison tautologies beyond equal literals (`2>1`, `or true`, `or 1`), MSSQL/Postgres-specific syntax, and a full expression precedence parser. DQ2 needs only what removes the measured FP classes and keeps the measured TPs.
- **Expected and accepted TP losses** (dev rows only `sqli.boolean-tautology` / `sqli.stacked-query` catch today, by accident): a JS prototype-pollution payload (`toString=toString`), an OGNL payload, an MVEL `Runtime.exec` payload (`; r.exec`), and a base64-in-JSON form value. Each needs a family DQ3 builds. They are listed by rel path in the justification table (§6.2).

### 4.4 Corroboration de-duplication

**What exists.** `score::arbitrate` counts one item per `(field, first pattern name)`; corroboration is `0.1 × Σrest`, capped at `scoring.corroboration_cap` (15). On one field, the graph item, the signature item, `ai.anomaly-score` and `api.type-violation` all corroborate each other. Yet `HeuristicOracle` adds 0.5 *because* a graph sink is reachable, and `api.type-violation` requires one.

**Change** in `score.rs`:

1. The counting key becomes `(origin field, family)`. The origin is the `FieldRef` with any `#…` derived suffix removed. Body leaves are separate parameters, so they are separate origins (D10).
2. Derived items, `ai.anomaly-score` and `api.type-violation`, never corroborate an item on the same origin. They still count as the top item if they are the strongest.
3. Items from chunks or split halves of one field collapse under (1).

No new option. `scoring.corroboration_cap` keeps its meaning.

**Measured by.** A/B against the pre-change scorer, run after §4.2 so the leaf split is in place. Expected ΔFP ≈ 0, because no single item scores between 55 and 70. The point of the change is to stop the leaf split from inflating benign scores. Report the dev score histogram and the Monitor count, and list every malicious row whose verdict falls (a corroboration-dependent TP is a justification row).

### 4.5 Per-context canonicalisation (P0)

**Included (D11). It is small:** `Normalized` gains `sql_text`, the comment-stripped view that is today's `text`. `text` keeps comments and only collapses whitespace. `analyze_with` tokenizes `sql_text` for `sql.rs` and `text` for the other sinks; when `flags.had_comment` is false the two are identical, so it tokenizes once. This closes the Plan B probe (an HTML comment hiding a tag from XSS sinks). It also takes `#` out of shell and XSS sight lines. The gate is the bypass-fix rule: its probe regression test blocks and it adds ≤ 0 dev FPs. If it adds FPs, it moves to DQ3 with the data.

## 5. Data flow

Raw request → `Request::fields()`:
- the body goes through `body_fields()`: binary → none; JSON, form and multipart → leaves; otherwise `<body>`.

Then per field: chunking → `normalize` (`text` plus `sql_text`) → tokenize → sinks. SQL candidates go through `sqlgate::confirm` and shell candidates through the command-position rule. Then the detectors run, followed by `arbitrate` with `(origin, family)` de-duplication, the verdict and `decided_by`. The eval CSV carries `cause/field/top/shadow` unchanged, and the new field names appear in `field`.

## 6. Error handling, testing and acceptance

### 6.1 Error handling

- **Grammar and gate parsers** are total. Recursion depth is capped at 32, with a token budget equal to the window size. A budget hit means "not confirmed" (the construct stays latent) and never panics. They are added to `tests/fuzz_props.rs`.
- **JSON parse failure or over-deep nesting** falls back to `<body>` and emits the informational `limit.body-unparsed` (none, 0 points), as the recall-lift design planned.
- **Malformed multipart** (no closing boundary) falls back to `<body>`.
- **Field caps** never drop text: overflow goes into the remainder field.

### 6.2 Measurement protocol (dev only until the end)

- **One step per change**, in this order: §4.3 shell rule → §4.3 SQL gate → §4.2 → §4.4 → §4.5. Each step is an A/B on `--manifest …/split/manifest.tsv --side dev`, toggled through `shield.disabled` on the gate and parse ids.
- **Recorded per step:**
  - ΔTP and ΔFP;
  - McNemar b, c and p for malicious and benign rows (`compare_runs.py`);
  - recall and FP-rate Wilson CIs;
  - `clusters.py --side dev --top 15` before and after.
- **Justification table.** Any malicious row that goes from Challenge/Block to Allow/Monitor gets a row: rel, construct, the reason it was lost, and the DQ phase that recovers it. The owner sees this table in `eval/RESULTS-DQ2.md`.
- **Leave-one-out.** `venusflytrap ablate --side dev` on the final build; the new ids appear in it automatically.
- **Robustness and latency.**
  - `bench_http` seeds and mutants: retained ≥ 96% and mutant recall ≥ 83.0%, or a justification row per lost mutant family.
  - Latency: library p95 < 1 ms on the full corpus.
- **Held-out** is scored **once**, after the last step, and reported separately. It is never opened for tuning.

### 6.3 Serve regression check (replaces the identity gate)

`eval/decision_gate.sh` gains a `diff` mode. It runs serve (distinct and pooled:100) and prints, for every changed decision, the rel path, label, old→new verdict and the new `cause/field/top`. The check passes when all of the following hold:

1. Every changed row is attributable to a DQ2 id. Its old or new `top` is one of the four sinks, `cause`/`field` names a reclassified body or header field, or the score moved only through the corroboration change.
2. `bans_from_allowed = 0` and `invariant_violations = 0`.
3. TCP replay (`--mode tcp`): `mismatch_block_vs_proxy_allow = 0`, with `mismatch_upstream_5xx`/`mismatch_io` at DQ1's level (0).
4. No malicious row changes outside the justification table.

### 6.4 Exit

- Dev FP ≤ ~0.6% (≤ 99 rows) with dev ΔTP ≥ 0 net of the listed justification rows, which the owner rules on.
- `cargo test --workspace` and `clippy -D warnings` green; eval/*.py unit tests green; TS bindings regenerated if `ConstructKind` reaches the wire.
- `eval/RESULTS-DQ2.md`: the per-step table, the justification table, ablation, held-out once, and serve/TCP checks.

**Unit tests:**
- body classes (protobuf with control bytes, printable "protobuf", gzip magic, text/plain JSON, ndjson, multipart with a binary part);
- the gate from all three states:
  - accepted: `1 or 1=1`, `x' or 'a'='a`, `0' || 2=1e1union select 1,2`, `1e1 union select a from b`, `rrr';select pg_sleep(5)`;
  - rejected: `site:x.com union select 关键字`, `the union select members from each`, `sql注入的“and 1=1，and 1=2”`, `1 and 1=1 is a very basic`, `format=json&id=v3`;
- the `(origin, family)` de-duplication;
- the P0 probe.

## 7. Decisions

| # | Decision | Reason |
|---|---|---|
| D1–D3 | (header grammar matrix: moved to DQ3 with §4.1, see D15) | — |
| D4 | One SQL fragment parser from three start states that must reach end of input (trailing re-balancing quote allowed) | A value concatenated into SQL must be valid SQL; this rejects the prose, search and telemetry classes behind 77 dev FPs |
| D5 | Gate only `union-select`, `boolean-tautology`, `stacked-query`; candidates that fail stay latent | These are the measured FP sinks; latent keeps them visible in the evidence |
| D6 | Non-ASCII identifiers are not SQL in the gate | Removes the CJK search FPs; attackers do not need them; a recorded trade-off |
| D7 | A bare identifier is not a valid prefix operand | Rejects English prose ("the union select …"); real injections lead with a number, quote, `)` or `null` |
| D8 | `cmd.chained-command` gets a shell command-position rule, not the SQL gate | All 37 dev FPs are `&id=`; a binary followed by `=` is an assignment or URL parameter, not a command |
| D9 | `sqli.quote-breakout` is not gated in DQ2 | Net +4 on dev with 11 unique TPs; revisit with the SQLi variants in DQ3 |
| D10 | Corroboration key is `(origin field, family)`; derived engines never corroborate their own field | AI and API-safety items are functions of the graph result, not independent evidence |
| D11 | Include P0 per-context canonicalisation | It is a ~1-module change with a known probe, gated at +0 dev FP |
| D12 | gzip and other compressed bodies get no text field; no decompressor | None is in `Cargo.lock`; 0 malicious dev bodies are compressed |
| D13 | Declared-binary bodies count as binary only when their bytes look binary | A Content-Type label alone must not hide a payload (parser-discrepancy evasion) |
| D14 | Changed constructs are measured by A/B through gate ids, not shadow mode | Shadow mode is for new constructs; gates make A/B a config switch on one build |
| D15 | The per-header grammar matrix (§4.1) is deferred to DQ3 | It decides no dev FP (`cmd.shell-meta` d_fp = 0) and would lower the scores of malicious rows just below `monitor_at`; DQ3 needs it as a guard for header-borne constructs |

## 8. Risks and what goes to DQ3

- **TP losses from the gate** are expected: 3–5 accidental TPs (JS, OGNL, MVEL, base64-in-JSON). Recovered by DQ3 base64 islands, deserialization/expression families and the XSS/JS tokenizer.
- **Overfitting to dev prose.** D6/D7 are justified by SQL semantics, not by the specific strings. Held-out is scored once, and template siblings can still flatter it (recall-lift §risks).
- **Body splitting adds fields**, so there is more surface for latent hits and for API-safety. This is controlled by D10 and measured.
- **The gate's coverage is MySQL-first.** MSSQL/Postgres syntax, time-delay, CASE, error-based and non-literal tautologies go to DQ3. So do the 33 remaining FPs (XSS 22, quote-breakout 10, traversal 1, with overlaps), which are out of DQ2's sinks.
- The per-header grammar matrix (§4.1, D15), configurable header lists, URL-structured Referer/Origin parsing, gzip decompression under size and ratio caps, and recursive JSON-in-field expansion as derived fields are all deferred to DQ3.
