# DQ5 fixes: comments and command chaining

Two engine fixes found while studying the dev attacks that CRS blocked and
Venusflytrap missed (DQ4 data, dev rows only). Neither adds a construct. Held-out
was not scored.

## What changed

1. **A comment no longer hides the text after it.** Comment canonicalization
   drops the rest of a line after `--` or ` #`, and the rest of the field after an
   unterminated `/*`, before the token graph runs. Anything after such a marker
   reached no sink. When a comment was stripped, `Normalized::kept` now holds the
   field with comments kept, and `graph::analyze_field` adds the constructs formed
   there. It takes only formed constructs (no latents) and none of the SQL family:
   SQL reads comments as comments, and its sinks read the stripped text. The
   view is the decoder `decode.keep-comments`, so `--disable decode.keep-comments`
   restores the old behaviour.
2. **Command chaining tries every separator.** `binary_after_meta` returned at the
   first identifier after the first separator. A later separator followed by a
   known binary was never checked. `gate.cmd-position` still applies to every
   candidate.

## Dev A/B against main (`5ed6fc6`), library mode

| Run | TP | FP | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|
| main | 148 | 100 | 45.12 % [39.82, 50.53] | 0.602 % [0.495, 0.732] |
| both fixes | 150 | 100 | 45.73 % [40.42, 51.14] | 0.602 % [0.495, 0.732] |

- McNemar on malicious rows: 0 rows lost, 2 gained, p = 0.5. On benign rows: no change, p = 1.
- No malicious row falls from Challenge/Block to Allow/Monitor.
- The recall gain is not significant on its own. The main value of fix 1 is
  closing an evasion route, since a comment marker could hide any non-SQL
  construct after it.

An earlier version of fix 1 also took SQL constructs from the kept view. It
gained 6 TP but added 7 FP on dev, all of them `sqli.stacked-query`, so SQL was
excluded.

## Found along the way: a DQ4 caveat

CRS rule 920350 (Host header is a numeric IP address) fires on 276 of 328 dev
attack rows (84 %) but only on 29 of 16,521 dev benign rows (0.18 %), at PL1 with
threshold 20. In this corpus, the attack requests were mostly sent to a numeric-IP
Host. That is how the corpus was recorded, not a property of the attacks, so the
rule adds anomaly points to attack rows for free and inflates CRS recall in DQ4.
How much it inflates recall was not measured. A CRS rerun with 920350 removed
would measure it.

## Checks

- `cargo test --workspace`: 299 passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- New unit tests:
  - Each comment form hides nothing when the view is on, and does when it is off.
  - A benign comment adds nothing.
  - The kept view takes no SQL constructs.
  - Chaining finds a later separator, and separators with no binary stay latent.
