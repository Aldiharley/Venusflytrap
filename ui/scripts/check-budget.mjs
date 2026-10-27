// Budget gate (parent spec §5.10): initial JS <= 150 KB gz, each lazy chunk <= 80 KB gz.
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const manifest = JSON.parse(readFileSync('dist/.vite/manifest.json', 'utf8'));
const gz = (file) => gzipSync(readFileSync(`dist/${file}`)).length;
const kb = (n) => (n / 1024).toFixed(1);

const entry = Object.values(manifest).find((c) => c.isEntry);
if (!entry) throw new Error('no entry chunk in the manifest');
const seen = new Set();
const walk = (chunk) => {
  if (seen.has(chunk.file)) return;
  seen.add(chunk.file);
  for (const key of chunk.imports ?? []) walk(manifest[key]);
};
walk(entry);
const initial = [...seen].filter((f) => f.endsWith('.js')).reduce((sum, f) => sum + gz(f), 0);
let failed = initial > 150 * 1024;
console.log(`initial JS ${kb(initial)} KB gz (budget 150)${failed ? '  OVER' : ''}`);
for (const [key, chunk] of Object.entries(manifest)) {
  if (!chunk.isDynamicEntry) continue;
  const size = gz(chunk.file);
  const over = size > 80 * 1024;
  failed ||= over;
  console.log(`chunk ${key} ${kb(size)} KB gz (budget 80)${over ? '  OVER' : ''}`);
}
process.exit(failed ? 1 : 0);
