# Venusflytrap — Research & Feasibility Review

*Feasibility review of the Venusflytrap design, grounding each design claim in published work.*
*Author: Dennis Liu · Date: 2026-10-22*

## 0. The thesis under review

Venusflytrap's thesis: traditional WAFs *guess what the code looks like* (regex
signatures, or an AST parser that "silently passes" on parse failure), whereas
Venusflytrap *infers what the code can do* by building a relational/semantic
**graph** and checking whether attacker-controlled ("tainted") input reaches a
dangerous execution point.

The design claims, and whether each holds up:

| # | Claim | Short verdict |
|---|-------|---------------|
| C1 | Regex WAFs collapse under full-width chars, inline comments, multi-layer URL encoding | **True** — well documented |
| C2 | AST-parser WAFs "fail open" (silently pass) on malformed input | **Plausible/True in general**; depends on implementation |
| C3 | A token/relational **graph + taint reachability** detects attacks regardless of syntactic mutation | **Sound and established**; "regardless" is overstated |
| C4 | 14-layer decode + full charset normalization + homoglyph (Cyrillic-as-Latin) folding | **Feasible**; maps to Unicode UTS#39 confusables |
| C5 | **Four-valued evidence lattice** (none / safe / suspicious / dangerous) for arbitration | **Legitimate** — this is Belnap's four-valued logic |
| C6 | High-interaction honeypot + cross-request APT chain inference | **Feasible**; standard deception + kill-chain staging |
| C7 | Target metrics to beat: regex ~69% (→~10% under mutation), strict AST ~4% under mutation, with a semantic engine holding high recall under mutation at low false positives and sub-millisecond latency | **Directionally plausible, to be measured** — see §3 |

**Is the approach sound and buildable?** Yes — the *architecture* rests on real,
citable techniques. Any specific headline percentage is treated as a **target to
measure**, not a result to assume. Venusflytrap ships a **reproducible
benchmark** so its numbers are earned rather than quoted.

## 1. Claim-by-claim grounding

### C1 — Regex/signature WAFs are brittle (TRUE)
Decades of practitioner work show signature evasion via encoding, case, comment
insertion and fragmentation. Ivanov's *Web Application Firewalls: Analysis of
Detection Logic* (Black Hat US-16) is a canonical treatment. The recent
multi-vendor study (17 WAF configs, AWS/GCP/Azure/Cloudflare) found bypass rates
climbing from 17.6% (simple payloads) to 70.6% (parameter-pollution) and a
100% evasion rate for an automated "hackbot."

### C2 — AST/semantic parsers can fail open (PLAUSIBLE)
The article's specific mechanism — "parse fails → pass to avoid breaking
business traffic" — is a real fail-open risk but is implementation-specific,
not a law. The deeper, better-documented problem is **parser differential**:
the WAF and the backend disagree about how to parse the same bytes.
**WAFFLED** (Akhavani et al., 2503.10846; Northeastern + Dartmouth) weaponizes
exactly this, producing 1,207 bypasses affecting ~90% of sites by mutating
*innocuous* parts (multipart boundaries, charset, XML namespaces) so the WAF
sees benign data while the app reconstructs the exploit. Their fix —
`HTTP-Normalizer`, a re-parse/canonicalize proxy where "invalid states are
unrepresentable" — is the same normalization-first discipline Venusflytrap adopts.

### C3 — Graph + taint reachability (SOUND; "regardless" overstated)
Modeling input as a graph and asking "does a tainted source reach a dangerous
sink?" is the core of a large, credible literature:
- **SQLiGoT** (graph of tokens + SVM) — SQLi as a token graph with node centrality.
- **TaintRadar** (2607.16456) — taint-style detection on augmented Code Property
  Graphs; 80% accuracy, 29 zero-days on real PHP.
- **TChecker** (CCS'22), **Artemis** (2502.21026), **Yama** (2410.12351) —
  precise inter-procedural taint analysis for PHP.
- Google patents US7860842B2 / US10129285B2 — data-flow-graph SQLi detection and
  end-to-end taint tracking for injection.

Important nuance for honest framing: most of the above are *static source-code*
analyzers. Venusflytrap applies the same *idea* at runtime to the **request
payload** (closer to SQLiGoT and to Chaitin's **SQLChop**, a tokenizer+syntax
engine, now the core of the open-source **SafeLine** WAF — whose own published
detection is 71–76%, a useful reality check on any high recall target). The
"detects regardless of syntactic mutation" claim is too strong: adversarial-ML
work like **WAF-A-MoLE**
(Demetrio et al., 2020) evades token/ML detectors with semantics-preserving
mutations (case/whitespace/comment/operator swaps, logical invariants). The
honest target is "substantially more mutation-robust than regex," which is
exactly what the benchmark should demonstrate.

### C4 — Multi-layer decode + confusables folding (FEASIBLE)
Iterated decode (URL/entity/unicode-escape/base64) with a fixpoint and a depth
cap is standard. "Cyrillic-as-Latin" homoglyph folding is **Unicode UTS#39**
confusable *skeleton* mapping — a defined, implementable algorithm. "14 layers"
is a knob, not magic; the real requirements are (a) decode to a fixpoint with a
hard cap to avoid DoS, and (b) match the backend's decoding so you don't open a
parser differential while closing another.

### C5 — Four-valued evidence lattice (LEGITIMATE)
"None / safe / suspicious / dangerous" with weighted arbitration between an AI
verdict and deep-semantic verdict is a direct instance of **Belnap's
four-valued logic** (None=⊥, True, False, Both=⊤) with its two orderings:
a *truth* order and an *information/knowledge* order. Using the knowledge order
to **accumulate evidence monotonically** from multiple detectors (and represent
"sources disagree" as Both rather than crashing) is textbook and a clean fit for
multi-engine arbitration.

### C6 — Honeypot + APT chain inference (FEASIBLE)
High-interaction deception and mapping probes onto kill-chain stages are
mainstream (T-Pot, Glastopf lineage). An empty-payload scan of
`/actuator/configprops`, `/info.php`, `/.npmrc`, `/.git/`, `/.env` is exactly
what OWASP CRS flags via its
**restricted-files** list and rule **930130** — verified against the current CRS
data file (`.env`, `.git/`, `.npmrc`, `phpinfo.php` are all present). So
"empty-payload path probing → high intent score" is both real and standard.

### C7 — The numbers (TREAT AS TARGETS, NOT RESULTS)
- **"Zero false positives"** on a large benign set is not a property any serious
  engine should assert. Every engine trades FP vs FN; SafeLine reports non-zero
  FP, and libinjection's long CVE/bypass history (PortSwigger/Thinkst documented
  SQLi→XSS bypasses) shows even strong engines miss. We *measure* FP, not assert
  zero.
- **Sub-millisecond latency** is plausible for a Rust tokenizer+graph on small
  payloads; we measure p50/p95/p99 on the actual corpus.
- **High recall under mutation** is plausible but must be demonstrated. The
  benchmark exists to produce the number on an open corpus.

## 2. What a defensible build adds

1. **An open ground-truth corpus**, generated and documented, rather than a
   private one.
2. **A full confusion matrix** every run — FP is reported, never asserted zero.
3. **Baselines** (regex, tokenizer) run in the same harness for apples-to-apples
   comparison.
4. A clean Rust workspace implementing the architecture end to end
   (normalize → graph/taint → lattice → score → deceive/chain).

## 3. Feasibility verdict

**Build it — as a research-grade reference implementation, not a drop-in
enterprise WAF.** Every subsystem is grounded in citable work; the architecture
is coherent; the risks (parser differential, adversarial mutation, FP honesty)
are known and designed-for. The headline metrics are re-derived by our own
benchmark so the repo stands on measurement, not marketing.

## Sources
- WAFFLED — Exploiting Parsing Discrepancies to Bypass WAFs: https://arxiv.org/abs/2503.10846
- WAF-A-MoLE — Evading WAFs through Adversarial ML: https://arxiv.org/pdf/2001.01952
- TaintRadar (augmented CPG taint detection): https://arxiv.org/html/2607.16456
- TChecker (CCS'22): https://www.cse.cuhk.edu.hk/~wei/papers/ccs22_tchecker.pdf
- Artemis (PHP taint, SSRF): https://arxiv.org/pdf/2502.21026
- Yama (opcode data-flow PHP): https://arxiv.org/pdf/2410.12351
- SQLiGoT (graph of tokens + SVM): https://www.scribd.com/document/486846578/SQLiGoT-Using-TokenGraph-SVM
- Chaitin SQLChop: https://github.com/chaitin/sqlchop · SafeLine: https://github.com/chaitin/SafeLine
- libinjection: https://github.com/client9/libinjection · bypass history: https://citation.thinkst.com/talk/33393
- Ivanov, WAF Detection Logic (BH US-16): https://www.blackhat.com/docs/us-16/materials/us-16-Ivanov-Web-Application-Firewalls-Analysis-Of-Detection-Logic.pdf
- Belnap four-valued logic (survey): https://arxiv.org/pdf/2503.20679 · https://en.wikipedia.org/wiki/Four-valued_logic
- Unicode UTS#39 confusables: https://unicodefyi.com/guide/unicode-confusables-guide/
- OWASP CRS restricted-files / rule 930130: https://github.com/coreruleset/coreruleset
- Multi-vendor WAF bypass study: https://cybersecuritynews.com/wafs-protection-bypassed/
