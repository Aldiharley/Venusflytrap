# Venusflytrap console

Svelte 5 + Vite SPA. In this stage every screen reads deterministic fixtures through
`src/lib/api/source.ts` (`FixtureSource`); SP5 adds the HTTP + SSE source.

    npm install
    npm run dev          # http://localhost:5173 (append ?static to stop the simulated live feed)
    npm test             # unit and component tests (Vitest + jsdom)
    npm run check        # svelte-check, warnings fail
    npm run build && npm run budget   # initial JS <= 150 KB gz, each route chunk <= 80 KB gz
    npm run e2e          # Playwright on system Edge: axe (light + dark), CSP, keyboard, reduced motion

The e2e run builds first, serves `vite preview` on port 4173 (with the production CSP) and uses the
system Microsoft Edge, or Chrome with `PW_CHANNEL=chrome`; no browser download is needed.

Generated art (`assets/props`, `assets/scenes`) is not committed until its licence is
confirmed; the app builds without it and simply omits the images.
