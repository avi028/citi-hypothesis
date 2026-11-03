// Offline self-test of the diff pipeline (no browser, no ssh).
// Generates two synthetic screenshots, runs diffImages, asserts artifacts.
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PNG } from 'pngjs';
import { diffImages } from './verify.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, 'artifacts', '_selftest');
mkdirSync(outDir, { recursive: true });

const W = 300, H = 150;
function blank() {
  const p = new PNG({ width: W, height: H });
  for (let i = 0; i < W * H; i++) p.data[i * 4] = 240, p.data[i * 4 + 1] = 240, p.data[i * 4 + 2] = 240, p.data[i * 4 + 3] = 255;
  return p;
}
function rect(p, x, y, w, h, [r, g, b]) {
  for (let yy = y; yy < y + h; yy++) for (let xx = x; xx < x + w; xx++) {
    const k = (yy * W + xx) * 4;
    p.data[k] = r; p.data[k + 1] = g; p.data[k + 2] = b; p.data[k + 3] = 255;
  }
}

const before = blank();
rect(before, 20, 40, 60, 40, [200, 30, 30]);      // red card
rect(before, 10, 110, 40, 20, [30, 90, 200]);      // blue chip

const after = blank();
rect(after, 100, 40, 60, 40, [200, 30, 30]);       // red card moved right
rect(after, 10, 110, 40, 20, [30, 200, 90]);       // blue chip turned green
rect(after, 200, 90, 50, 30, [250, 200, 0]);       // new yellow tile

const bf = join(outDir, 'before.png');
const af = join(outDir, 'after.png');
writeFileSync(bf, PNG.sync.write(before));
writeFileSync(af, PNG.sync.write(after));

const res = diffImages(bf, af, outDir, { minRegion: 4, mergeGap: 24 });

let ok = true;
const check = (name, cond) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`); if (!cond) ok = false; };

check('diff.png exists', existsSync(join(outDir, 'diff.png')));
check('diff-marked.png exists', existsSync(join(outDir, 'diff-marked.png')));
check('changedPct > 0', res.changedPct > 0);
// moved card (2 boxes, merged by gap<=24) + chip + tile => 3 regions
check(`3 regions found (got ${res.regions.length})`, res.regions.length === 3);
check('regions carry index/coords', res.regions.every(r => r.index > 0 && r.w > 0 && r.h > 0));

const marked = PNG.sync.read(readFileSync(join(outDir, 'diff-marked.png')));
let redPixels = 0;
for (let i = 0; i < marked.width * marked.height; i++) {
  if (marked.data[i * 4] > 200 && marked.data[i * 4 + 1] < 80 && marked.data[i * 4 + 2] < 80) redPixels++;
}
check('marked image has red box/annotation pixels', redPixels > 500);

console.log(`\nchangedPct=${res.changedPct}% regions=${res.regions.length}`);
console.log(ok ? '\nSELF-TEST OK' : '\nSELF-TEST FAILED');
process.exit(ok ? 0 : 1);