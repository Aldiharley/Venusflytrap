# SDD ledger — plan: M:/Projects/venusflytrap/docs/superpowers/plans/2026-10-27-sp6a-console-shell.md
Worktree: M:/Projects/venusflytrap-sp6a (branch sp6a-console-shell, from main b2f82ff). Assets copied untracked.
Task 1: dispatched (BASE b2f82ff, implementer aa50d06e89de78588, sonnet)
Task 1: owner ran the dependency install; resuming implementer
Task 1: PAUSED by owner — npm 11.1.0 resolver crash (edgesOut); owner will run the dependency step with npm 11.21.0 and say when done. Files written, uncommitted; implementer aa50d06e89de78588 to resume.
Task 1: RESUMED — owner installed with npm 11.21.0 (121 packages, lockfile present, pins verified)
Task 1: minor (deferred): check-budget walks static imports only (lazy chunks gated individually) — plan-mandated
Task 1: minor (deferred): app.test.ts is a smoke test only — plan-mandated
Task 1: minor (deferred): no .gitattributes; CRLF warnings on Windows
Task 1: note: tsconfig gained "allowJs": true (svelte-check could not resolve .svelte imports otherwise)
Task 1: complete (commits b2f82ff..928020f, review clean)
Task 2: note: vite.config test.css.include [/tokens\.css/] added (Vitest blanks CSS ?raw); vite-env.d.ts not needed
Task 2: minor (deferred, OWNER design-system finding): light danger on surface-base 4.31:1, accent on surface-sunken 4.10:1 — not in PAIRS; axe may flag later
Task 2: minor (deferred): /tokens\.css/ regex unanchored
Task 2: minor (deferred): :focus-visible box-shadow replaces .btn shadow while focused — plan-mandated
Task 2: minor (deferred): Motion.reduced not reactive to OS media change
Task 2: minor (deferred): theme stored()/apply-on-load path untested
Task 2: complete (commits 928020f..092a892, review clean; woff2/budget verified by controller)
Task 3: note: commit trailer reads "Claude Sonnet 5.5" (implementer model) — accepted as accurate, not amended
Task 3: minor (deferred): fmtRps rounding boundary (9.96 -> "10.0/s", 0.04 -> "0.0/s")
Task 3: minor (deferred): FixtureSource returns shared mutable fixture objects; counters() static vs jittered live; bans/stage_counts not updated live; extra subscribe advances shared board
Task 3: minor (deferred): fixture series totals don't reconcile with top_paths; rounding breaks by_verdict sums
Task 3: minor (deferred): type named Location shadows DOM global
Task 3: minor (deferred): test gaps — format boundaries, stage:null fixture, registry-id guard, real-timer live test
Task 3: complete (commits 092a892..26fb8f9, review clean; BanView matches UX G8)
Task 4: review — 4 Important (plan-mandated): router decode throw, focus-to-h1 race on lazy chunks, app.start/stop race + no catch, missing toast/Keys tests; plan doc Toasts->ToastStack updated
Task 4: fix round 1/5 (4 addressed, 0 open — router decode, focus after lazy load, start/stop gen guard + error/Retry, toast/Keys/aria-current tests; commits fca384a..c4f945d)
Task 4: note: components/Toasts.svelte renamed ToastStack.svelte (Windows case collision with toasts.svelte.ts); plan doc updated
Task 4: note: screens now render inside {#key router.path}<div> wrapper (remount per path)
Task 4: minor (deferred): focusPending not cleared if navigation happens before ready / import fails; Retry drops focus to body
Task 4: minor (deferred): toast live regions inserted with content; no hover pause; Link intercepts external/target/download hrefs; trailing-slash routes -> notfound; Live label logic duplicated in TopBar/NavRail; literal px sizes (plan-mandated); Placeholder gets undeclared param prop
Task 4: complete (commits 26fb8f9..c4f945d, review clean after 1 fix round)
Task 5: review — 2 Important: StageChip aria-label on role-less span (fix: role="img", additive, realises the plan's required name), no accessible-name test
Task 5: note: brief Interfaces said KpiTile href?, code block has note — code governs, no tile is clickable yet
Task 5: minor (deferred): Region untested + Math.random id ($props.id available); 1.5px literal vs --vf-bw-strong; stale state opacity-only (contrast risk); EmptyState img lacks height; hexagon filled vs outlined; diamond legibility unverified
Task 5: fix round 1/5 (2 addressed, 0 open — StageChip role="img", accessible-name + distinct-glyph tests; commits 3ad97cf..d7795dc; controller re-ran components.test.ts: 9/9)
Task 5: complete (commits c4f945d..d7795dc, review clean after 1 fix round)
Task 6: note: svelte-ignore a11y_no_noninteractive_tabindex on the scrollable table region (needed for axe scrollable-region-focusable); app.test Retry assertion now targets the "Requests over time" region
Task 6: minor (deferred): dashboard tests don't cover range/?from&to, link hrefs, 60 s refresh, banner, empty state, aria-hidden, legend totals (plan-mandated test)
Task 6: minor (deferred): load() has no stale-response guard or error handling (matters with a real DataSource)
Task 6: minor (deferred): empty state only on Top constructs; bans/honeypot show 0 before data; chart grid unlabeled, non-scaling-stroke, degenerate inputs; time cell td not th; fmtClock ambiguous on 7 d; unsound tone cast; fmtRps unit stripping; aria-label on plain dl
Task 6: complete (commits d7795dc..118d1f4, review clean)
Task 7: controller visual check (dev server, 1440x900, light + dark, ?static): layout matches canvas board; dark theme OK; pinned Exploitation card OK; no console errors.
Task 7: visual finding: legend overlaps route4 (/account) and hp3 (/phpmyadmin) at 1440 wide
Task 7: visual finding: near-zero flows label "0.0/s" (fmtRps rounding, Task 3 minor) — misleading on the map
Task 7: review — 4 Important (Esc reopens card; unpinned card stranded on Tab-out; Pause flips map->table [plan code vs spec]; derived line labels lack approx. [plan code vs E7]) — controller ruled 3–4 as plan-code bugs against the plan's own requirements, fixed in round 1 with visual findings + fmtRps <0.1, hatch pointer-events, halo by id
Task 7: minor (deferred): hover card unreachable by mouse; arrowing while pinned leaves old card pinned; Safari click-focus; Clean/Tower accessible-name wording; table twin omits card numbers; trivially-passing countText includes; ORDER duplicated; toolbar without roving; nested aside landmark; h3 before h2; possible rate-label stacking on 4-line bundle; card clipping near bottom
Task 7: controller visual re-check after 2e67f0e: legend below scene, no props covered; approx./< 0.1/s chips render
Task 7: fix round 1/5 (8 addressed, 0 open — Esc restore guard, scene focusout, motion.osReduced default, approx. chips (stub Challenge exact), legend below scene, fmtRps "< 0.1/s", hatch pointer-events, halo by node id; commits f1c2039..2e67f0e)
Task 7: minor (deferred): pinned card has no keyboard dismiss once focus leaves the scene; hover leave/enter while focus in card drops focus to body; null relatedTarget closes card; osReduced not live
Task 7: complete (commits 118d1f4..2e67f0e, review clean after 1 fix round; controller visual check light+dark)
Task 8: controller visual check (dev, 1440x900 dark, live feed): sort/ban badges/stage badges OK; freeze + pending bar + R apply keeps focus on key OK
Task 8: visual finding: grid overflows horizontally at 1440 (Last seen column cut off)
Task 8: visual finding: IPv6 row renders key and ip run together ("2001:db8:4f::/642001:db8:4f::17")
Task 8: note: pending bar re-appears instantly after apply because the fixture bumps last_seen every tick (fixture artefact)
Task 8: review — 3 Important (plan code vs plan requirements): Apply button unmounts before click + focus lost; zero tab stops when order shrinks; per-second Intl re-render cost at 500 rows — ruled fix-toward-plan, round 1 also folds in the 2 visual findings + minors (left-board label, current-stage SR, Ctrl+R guard, pluralise)
Task 8: minor (deferred): pending bar announces ~1/s and counts shifted rows; comment says order untracked but reconcile iterates the proxy; EmptyState flashes on first paint; filtered empty state copy misleading; ?stage= unvalidated; raw px sizes; class:banned has no CSS; thin screen tests
Task 8: fix round 1/5 (6 addressed, 0 open — region-wide freeze + apply focus restore, clamped active cell, cached Intl + per-cell text, no h-scroll at 1440, IPv6 ip on own line, minors; commits 8dc1bbc..8735af5)
Task 8: controller live check (Edge pane, 1440x900): scrollWidth=clientWidth 1174; real mouse click on Apply re-sorts and keeps focus on the same key's cell
Task 8: minor (deferred): Safari / Firefox-mac don't focus buttons on mousedown -> Apply click still lost there (one-line fix: preventDefault on mousedown); Enter on left-board row navigates to a gone source; key/ip read without separator; chains.test restores app.board only at end; R-with-modifier and pluralisation untested
Task 8: complete (commits 2e67f0e..8735af5, review clean after 1 fix round)
Task 9: review — 2 Important (test-only): reduced-motion check vacuous on zero packets; axe wait satisfied by loading-shell h1 — fix round 1 also asserts scheme + README note
Task 9: note: axe Page cast (duplicate playwright-core 1.64.0/1.64.1) and local declare const process accepted; dedupe via package.json overrides later (needs owner-run install)
Task 9: minor (deferred): no CSP negative control; keyboard test starts from programmatic focus; trailer mixed Sonnet/Opus across commits (cosmetic)
Task 9: fix round 1/5 (4 addressed, 0 open — packet count + no-preference control, per-route mounted waits, scheme assertion, README; commits 132c31b..0e7d9c3)
Task 9: minor (deferred): packet count() not auto-retrying; /monitor wait tied to placeholder copy (update in SP6b)
Task 9: controller full verification at 0e7d9c3: vitest 152/152, svelte-check 0/0, build ok, budget initial 29.3 KB (chunks 0.4–7.3), e2e 14/14 on Edge
Task 9: complete (commits 8735af5..0e7d9c3, review clean after 1 fix round)
FINAL REVIEW: dispatched (merge base b2f82ff, head 0e7d9c3)
FINAL REVIEW: Ready with fixes — Important: live label 4 copies / 2 meanings; M1 gitignore unlicensed art (before merge); M2 commit the plan (owner's call); M3–M8 + triaged deferred minors -> SP6b list in the review (DataSource error/abort contract = first SP6b task)
FINAL FIX WAVE: dispatched (Important #1 + M1), base 0e7d9c3
FINAL FIX WAVE: re-review all addressed (commit 75cd481); art-ignore build question answered by import.meta.glob design. SP6a DONE.
