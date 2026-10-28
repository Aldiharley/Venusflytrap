# Venusflytrap console

Svelte 5 + Vite SPA. In this stage every screen reads deterministic fixtures through
`src/lib/api/source.ts` (`FixtureSource`); SP5 adds the HTTP + SSE source.

Wire types come from `src/gen` (generated from vft-core by ts-rs; never edit by hand, check with
`cargo test -p vft-core --features ts --test ts_bindings`). `src/lib/api/types.ts` re-exports them and
adds the provisional view types. Every `DataSource` call takes `{ signal }` and fails with a typed
`SourceError`; screens load through `Latest`, which aborts the previous call and drops stale responses.

    npm install
    npm run dev          # http://localhost:5173 (append ?static to stop the simulated live feed)
    npm test             # unit and component tests (Vitest + jsdom)
    npm run check        # svelte-check, warnings fail
    npm run build && npm run budget   # initial JS <= 150 KB gz, each route chunk <= 80 KB gz
    npm run e2e          # Playwright on system Edge: axe (light + dark), CSP, keyboard, reduced motion

The e2e run builds first, serves `vite preview` on port 4173 (with the production CSP) and uses the
system Microsoft Edge, or Chrome with `PW_CHANNEL=chrome`; no browser download is needed.

Screenshots: the images in `../docs/images` are regenerated with `npm run screenshots` (system Edge; the
preview from `npm run build && npm run preview` must be running).

Generated art (`assets/props`, `assets/scenes`) is not committed until its licence is
confirmed; the app builds without it and simply omits the images.
