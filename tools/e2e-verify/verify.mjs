// citi-hypothesis e2e verification
//
//   node verify.mjs login    --config config.json          # establish a Qualys session (manual or env creds)
//   node verify.mjs baseline --config config.json [--url U] [--out DIR]
//   node verify.mjs run      --config config.json --cmd "remote shell command" [options]
//
// `run` flow:
//   1. capture BEFORE screenshot of the console page
//   2. execute the lab command over SSH (key auth, BatchMode)
//   3. wait --settle seconds (or poll until the UI changes, see --poll)
//   4. capture AFTER screenshot
//   5. pixel-diff -> diff.png (changed pixels) + diff-marked.png (changed regions boxed & numbered)
//   6. write summary.json + print a short report
//
// Browser uses a persistent profile (browser.userDataDir) so the Qualys SSO
// session survives between runs. If not logged in, the tool pauses and asks
// you to log in manually in the window that opens.

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import pixelmatch from 'pixelmatch';
import { PNG } from 'pngjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- config

// minimal .env loader (no dependency) — values in .env never override real env
function loadDotEnv() {
  const envFile = join(__dirname, '.env');
  if (!existsSync(envFile)) return;
  for (const line of readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    const [, key, val] = m;
    if (process.env[key] === undefined) process.env[key] = val;
  }
}

function loadConfig(path) {
  const cfg = JSON.parse(readFileSync(path, 'utf8'));
  const env = process.env;

  cfg.ssh ??= {};
  cfg.ssh.host = env.SSH_HOST ?? cfg.ssh.host;
  cfg.ssh.user = env.SSH_USER ?? cfg.ssh.user;
  cfg.ssh.port = Number(env.SSH_PORT ?? cfg.ssh.port ?? 22);
  cfg.ssh.identityFile = env.SSH_KEY ?? cfg.ssh.identityFile;

  cfg.browser ??= {};
  cfg.browser.channel = env.BROWSER_CHANNEL ?? cfg.browser.channel ?? 'msedge';
  cfg.browser.headless = env.HEADLESS === '1' || (cfg.browser.headless ?? false);
  cfg.browser.userDataDir = cfg.browser.userDataDir ?? '.session';

  cfg.page ??= {};
  cfg.diff ??= {};
  return cfg;
}

function die(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        a[key] = next;
        i++;
      } else {
        a[key] = true;
      }
    } else {
      a._.push(arg);
    }
  }
  return a;
}

// ---------------------------------------------------------------- helpers

function waitForEnter(prompt) {
  return new Promise((res) => {
    console.log(`\n>>> ${prompt}`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question('>>> (press Enter when ready) ', () => { rl.close(); res(); });
  });
}

async function openBrowser(cfg) {
  const b = cfg.browser;
  const opts = {
    headless: b.headless,
    viewport: b.viewport ?? { width: 1600, height: 1000 },
  };
  if (b.channel && b.channel !== 'chromium') opts.channel = b.channel;
  const profile = join(__dirname, b.userDataDir);

  const launch = (dir) => chromium.launchPersistentContext(dir, opts);

  try {
    return await openBrowserWithFallback(launch, profile, opts, b);
  } catch (err) {
    // profile held by a running session daemon? use a throwaway profile
    if (/lock|in use|singleton|Singleton|profile/i.test(err.message)) {
      const tmp = join(__dirname, `.session-tmp-${Date.now()}`);
      console.warn(`profile "${b.userDataDir}" is locked (session daemon running?) — using throwaway profile for this run (auto-login will re-establish the session).`);
      try {
        return await openBrowserWithFallback(launch, tmp, opts, b);
      } catch (e2) {
        throw e2;
      }
    }
    throw err;
  }
}

async function openBrowserWithFallback(launch, profile, opts, b) {
  try {
    const ctx = await launch(profile);
    const page = ctx.pages()[0] ?? (await ctx.newPage());
    return { ctx, page };
  } catch (err) {
    if (opts.channel) {
      console.warn(`channel "${b.channel}" failed (${err.message.split('\n')[0]}) — retrying with bundled chromium.`);
      delete opts.channel;
      const ctx = await launch(profile);
      const page = ctx.pages()[0] ?? (await ctx.newPage());
      return { ctx, page };
    }
    console.error(`browser launch failed: ${err.message}`);
    console.error('hint: run  npx playwright install chromium  to download the bundled browser,');
    console.error('      or set browser.channel to "msedge"/"chrome" to use your installed browser.');
    throw err;
  }
}

// poll until the login page is left behind (Qualys takes ~10-20s)
async function waitForLoginComplete(page, timeoutMs = 45000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (!/(login|signin)/i.test(page.url())) {
      await page.waitForTimeout(6000); // let the portal app settle
      return true;
    }
    await page.waitForTimeout(2000);
  }
  return false;
}

async function autoLogin(page, cfg) {
  const l = cfg.login ?? {};
  const user = l.usernameEnv ? process.env[l.usernameEnv] : undefined;
  const pass = l.passwordEnv ? process.env[l.passwordEnv] : undefined;
  if (user && pass && l.usernameSelector && l.passwordSelector) {
    await page.goto(l.url, { waitUntil: 'domcontentloaded' }).catch(() => {});
    await page.fill(l.usernameSelector, user);
    await page.fill(l.passwordSelector, pass);
    if (l.submitSelector) await page.click(l.submitSelector);
    const ok = await waitForLoginComplete(page);
    if (!ok) console.warn('warning: still on the login page after 45s — login may have failed');
    return ok;
  }
  return false;
}

// a visible password field is the strongest "we are not logged in" signal
function looksLikeLoginPage(page) {
  return page.locator('input[type="password"]:visible').count().then((n) => n > 0);
}

async function ensureLoggedIn(page, url, cfg) {
  await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 }).catch(() => {});
  await page.waitForTimeout(1200);
  if (!(await looksLikeLoginPage(page))) return;

  const ok = await autoLogin(page, cfg);
  if (!ok) {
    await waitForEnter('login required — log in manually in the browser window.');
  }
  await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 }).catch(() => {});
  await page.waitForTimeout(1500);
  if (await looksLikeLoginPage(page)) {
    console.warn('warning: still on a login page after logging in — check credentials/session.');
  }
}

async function capture(page, url, outFile, cfg) {
  const p = cfg.page ?? {};
  await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 }).catch(() =>
    page.waitForLoadState('domcontentloaded')
  );
  await page.waitForTimeout(p.settleMs ?? 2500);
  await page.screenshot({ path: outFile, fullPage: p.fullPage ?? false });
  console.log(`captured  ${outFile}`);
}

// ---------------------------------------------------------------- ssh

function runRemote(cfg, cmd, cmdFile) {
  return new Promise((resolvePromise, reject) => {
    const s = cfg.ssh;
    const args = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20'];
    if (s.identityFile) args.push('-i', s.identityFile, '-o', 'IdentitiesOnly=yes');
    if (s.port && s.port !== 22) args.push('-p', String(s.port));
    const target = `${s.user}@${s.host}`;

    if (cmdFile) {
      args.push(target, 'bash -s');
    } else {
      args.push(target, cmd);
    }

    console.log(`ssh ${target}: ${cmdFile ? `< ${cmdFile}` : cmd}`);
    // SSH_BIN lets you substitute a fake ssh (e.g. smoke tests): SSH_BIN="node smoke-ssh.mjs"
    const sshBin = process.env.SSH_BIN || 'ssh';
    const [bin, ...binArgs] = sshBin.split(/\s+/);
    const child = spawn(bin, [...binArgs, ...args], { stdio: cmdFile ? ['pipe', 'inherit', 'inherit'] : 'inherit' });
    if (cmdFile) {
      child.stdin.on('error', () => {}); // remote closed stdin early — ignore
      child.stdin.write(readFileSync(cmdFile));
      child.stdin.end();
    }
    child.on('error', reject);
    child.on('exit', (code) =>
      code === 0 ? resolvePromise() : reject(new Error(`ssh exited with code ${code}`))
    );
  });
}

// ---------------------------------------------------------------- diff

function loadPng(p) {
  return PNG.sync.read(readFileSync(p));
}

// Find connected regions of changed pixels and return their bounding boxes.
function findChangedRegions(diffImg, { minRegion = 8, mergeGap = 24 } = {}) {
  const { width: w, height: h, data } = diffImg;
  const visited = new Uint8Array(w * h);
  const boxes = [];

  for (let i = 0; i < w * h; i++) {
    if (visited[i] || data[i * 4 + 3] === 0) continue;
    const stack = [i];
    visited[i] = 1;
    let x0 = i % w, x1 = x0, y0 = (i / w) | 0, y1 = y0, count = 0;
    while (stack.length) {
      const j = stack.pop();
      const x = j % w, y = (j / w) | 0;
      if (x < x0) x0 = x; if (x > x1) x1 = x;
      if (y < y0) y0 = y; if (y > y1) y1 = y;
      count++;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const nx = x + dx, ny = y + dy;
          if (nx < 0 || ny < 0 || nx >= w || ny >= h) continue;
          const k = ny * w + nx;
          if (!visited[k] && data[k * 4 + 3] > 0) { visited[k] = 1; stack.push(k); }
        }
      }
    }
    if (count >= minRegion) boxes.push({ x: x0, y: y0, w: x1 - x0 + 1, h: y1 - y0 + 1, count });
  }

  // merge boxes that are close to each other
  let merged = true;
  while (merged) {
    merged = false;
    outer:
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i], b = boxes[j];
        const gapX = Math.max(0, a.x - (b.x + b.w), b.x - (a.x + a.w));
        const gapY = Math.max(0, a.y - (b.y + b.h), b.y - (a.y + a.h));
        if (gapX <= mergeGap && gapY <= mergeGap) {
          const u = {
            x: Math.min(a.x, b.x),
            y: Math.min(a.y, b.y),
            w: Math.max(a.x + a.w, b.x + b.w) - Math.min(a.x, b.x),
            h: Math.max(a.y + a.h, b.y + b.h) - Math.min(a.y, b.y),
            count: a.count + b.count,
          };
          boxes.splice(j, 1);
          boxes[i] = u;
          merged = true;
          break outer;
        }
      }
    }
  }
  return boxes;
}

// tiny 3x5 bitmap font (digits only) so region numbers are readable on the image
const FONT = {
  0: [1,1,1, 1,0,1, 1,0,1, 1,0,1, 1,1,1],
  1: [0,1,0, 1,1,0, 0,1,0, 0,1,0, 1,1,1],
  2: [1,1,1, 0,0,1, 1,1,1, 1,0,0, 1,1,1],
  3: [1,1,1, 0,0,1, 1,1,1, 0,0,1, 1,1,1],
  4: [1,0,1, 1,0,1, 1,1,1, 0,0,1, 0,0,1],
  5: [1,1,1, 1,0,0, 1,1,1, 0,0,1, 1,1,1],
  6: [1,1,1, 1,0,0, 1,1,1, 1,0,1, 1,1,1],
  7: [1,1,1, 0,0,1, 0,1,0, 0,1,0, 0,1,0],
  8: [1,1,1, 1,0,1, 1,1,1, 1,0,1, 1,1,1],
  9: [1,1,1, 1,0,1, 1,1,1, 0,0,1, 1,1,1],
};
function drawNumber(img, x, y, num) {
  const s = 2, pad = 1;
  const digits = String(num).split('').map(Number);
  for (const d of digits) {
    const pat = FONT[d];
    for (let r = 0; r < 5; r++) {
      for (let c = 0; c < 3; c++) {
        if (!pat[r * 3 + c]) continue;
        for (let dy = 0; dy < s; dy++) {
          for (let dx = 0; dx < s; dx++) {
            const px = x + c * s + dx, py = y + r * s + dy;
            if (px < 0 || py < 0 || px >= img.width || py >= img.height) continue;
            const k = (py * img.width + px) * 4;
            img.data[k] = 255; img.data[k + 1] = 0; img.data[k + 2] = 0; img.data[k + 3] = 255;
          }
        }
      }
    }
    x += 3 * s + pad;
  }
}

function drawBox(img, box, thickness = 2) {
  const { x, y, w, h } = box;
  for (let t = 0; t < thickness; t++) {
    for (let px = x; px < x + w; px++) {
      for (const py of [y + t, y + h - 1 - t]) {
        if (px < 0 || px >= img.width || py < 0 || py >= img.height) continue;
        const k = (py * img.width + px) * 4;
        img.data[k] = 255; img.data[k + 1] = 0; img.data[k + 2] = 0; img.data[k + 3] = 255;
      }
    }
    for (let py = y; py < y + h; py++) {
      for (const px of [x + t, x + w - 1 - t]) {
        if (px < 0 || px >= img.width || py < 0 || py >= img.height) continue;
        const k = (py * img.width + px) * 4;
        img.data[k] = 255; img.data[k + 1] = 0; img.data[k + 2] = 0; img.data[k + 3] = 255;
      }
    }
  }
}

// Full diff pipeline: pixelmatch -> diff.png, changed regions -> diff-marked.png
function diffImages(beforePath, afterPath, outDir, diffOpts = {}) {
  const before = loadPng(beforePath);
  const after = loadPng(afterPath);
  if (before.width !== after.width || before.height !== after.height) {
    throw new Error(
      `screenshot dimensions differ (${before.width}x${before.height} vs ${after.width}x${after.height}) — ` +
      `use the same viewport and fullPage settings for both captures`
    );
  }
  const { width: w, height: h } = before;
  // pass 1: clean change mask (unchanged pixels fully transparent) for region detection
  const mask = new PNG({ width: w, height: h });
  const changedPx = pixelmatch(before.data, after.data, mask.data, w, h, {
    threshold: diffOpts.threshold ?? 0.1,
    diffMask: true,
  });
  const changedPct = ((changedPx / (w * h)) * 100);
  const regions = findChangedRegions(mask, diffOpts);

  // pass 2: visual diff overlay (red tint over after-image) for human viewing
  const visual = new PNG({ width: w, height: h });
  pixelmatch(before.data, after.data, visual.data, w, h, {
    threshold: diffOpts.threshold ?? 0.1,
  });
  const diffFile = join(outDir, 'diff.png');
  writeFileSync(diffFile, PNG.sync.write(visual));

  const marked = PNG.sync.read(readFileSync(afterPath));
  regions.forEach((box, i) => {
    drawBox(marked, box);
    // number tag: above the box, or inside it when the box hugs the top edge
    const tagY = box.y >= 14 ? box.y - 12 : box.y + 2;
    const tagX = box.x + 2;
    drawNumber(marked, tagX, tagY, i + 1);
  });
  const markedFile = join(outDir, 'diff-marked.png');
  writeFileSync(markedFile, PNG.sync.write(marked));

  return {
    changedPx,
    changedPct: Number(changedPct.toFixed(4)),
    regions: regions.map((b, i) => ({ index: i + 1, ...b })),
    diffFile,
    markedFile,
  };
}

// ---------------------------------------------------------------- session

// Attach to a running `session` daemon over CDP. Returns null if none is up.
async function attachToSession(cfg) {
  const port = cfg.browser?.cdpPort;
  if (!port) return null;
  try {
    const browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 5000 });
    const ctx = browser.contexts()[0];
    const page = ctx?.pages()[0];
    if (!ctx || !page) {
      await browser.close();
      return null;
    }
    console.log(`attached to live session daemon (:${port})`);
    return { browser, ctx, page };
  } catch {
    return null;
  }
}

// One persistent, logged-in browser window kept open. `run`/`baseline` attach
// to it over CDP, so the Qualys session (and the tab you can watch) survives.
async function cmdSession(cfg) {
  const b = cfg.browser;
  const port = Number(b?.cdpPort ?? 9222);
  const profile = join(__dirname, b.userDataDir);
  const ctx = await chromium.launchPersistentContext(profile, {
    channel: b.channel,
    headless: b.headless,
    viewport: b.viewport ?? { width: 1600, height: 1000 },
    args: [`--remote-debugging-port=${port}`, '--remote-allow-origins=*'],
  });
  const page = ctx.pages()[0] ?? (await ctx.newPage());
  await ensureLoggedIn(page, cfg.page?.url ?? cfg.login?.url, cfg);

  console.log(`\nsession daemon ready: http://127.0.0.1:${port} — keep this window open.`);
  console.log('now run:  node verify.mjs run --config config.json --page file --cmd "..."\n');
  const stop = () => {
    console.log('\nclosing session…');
    ctx.close().then(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  await new Promise(() => {}); // idle forever
}

// ---------------------------------------------------------------- commands

async function cmdLogin(cfg) {
  const { ctx, page } = await openBrowser(cfg);
  const l = cfg.login ?? {};
  if (!l.url) die('login.url not set in config');
  const ok = await autoLogin(page, cfg);
  if (!ok) {
    await waitForEnter('open browser is at the login page — log in manually (SSO/MFA ok), then confirm.');
  }
  console.log('session saved in the persistent profile — subsequent runs reuse it.');
  await ctx.close();
}

async function cmdBaseline(cfg, a) {
  const url = a.url ?? cfg.page?.urls?.[a.page] ?? cfg.page?.url;
  if (!url) die('no page url: pass --url, --page, or set page.url in config');
  const outDir = resolve(a.out ?? join(__dirname, 'artifacts', 'baseline'));
  mkdirSync(outDir, { recursive: true });
  const sess = await attachToSession(cfg);
  let handle;
  if (sess) {
    handle = { page: sess.page, close: () => sess.browser.close() };
  } else {
    const { ctx, page } = await openBrowser(cfg);
    handle = { page, close: () => ctx.close() };
  }
  try {
    await ensureLoggedIn(handle.page, url, cfg);
    await capture(handle.page, url, join(outDir, 'before.png'), cfg);
    console.log(`baseline -> ${join(outDir, 'before.png')}`);
  } finally {
    await handle.close();
  }
}

async function cmdRun(cfg, a) {
  const url = a.url ?? cfg.page?.urls?.[a.page] ?? cfg.page?.url;
  const cmd = a.cmd;
  const cmdFile = a['cmd-file'];
  if (!url) die('no page url: pass --url, --page, or set page.url in config');
  if (!cmd && !cmdFile) die('nothing to run: pass --cmd "remote command" or --cmd-file script.sh');
  if (!cfg.ssh?.host || !cfg.ssh?.user) die('ssh host/user not configured (config file or SSH_HOST/SSH_USER env)');

  const outDir = resolve(a.out ?? join(__dirname, 'artifacts', 'run'));
  mkdirSync(outDir, { recursive: true });
  const beforeFile = join(outDir, 'before.png');
  const afterFile = join(outDir, 'after.png');
  const settleMs = Number(a.settle ?? cfg.page?.settleMs ?? 5000);
  const poll = !!a.poll;
  const pollInterval = Number(a['poll-interval'] ?? 5) * 1000;
  const pollMax = Number(a['poll-max'] ?? 120) * 1000;
  const changedGoal = Number(a['changed-pct'] ?? 0.5); // poll exits when changed % >= this

  const sess = await attachToSession(cfg);
  let handle;
  if (sess) {
    handle = { page: sess.page, close: () => sess.browser.close() };
  } else {
    const { ctx, page } = await openBrowser(cfg);
    handle = { page, close: () => ctx.close() };
  }
  try {
    await ensureLoggedIn(handle.page, url, cfg);
    await capture(handle.page, url, beforeFile, cfg);

    await runRemote(cfg, cmd, cmdFile);

    if (poll) {
      console.log(`polling for UI change (goal >= ${changedGoal}% pixels changed, max ${pollMax / 1000}s)…`);
      const start = Date.now();
      let best = -1;
      while (Date.now() - start < pollMax) {
        await capture(handle.page, url, afterFile, cfg);
        let pct = -1;
        try {
          pct = diffImages(beforeFile, afterFile, outDir, cfg.diff).changedPct;
        } catch (e) {
          throw e;
        }
        console.log(`  changed so far: ${pct}%`);
        best = Math.max(best, pct);
        if (pct >= changedGoal) break;
        await handle.page.waitForTimeout(pollInterval);
      }
      console.log(best < changedGoal
        ? `note: never reached ${changedGoal}% changed (max observed ${best}%) — using last frame.`
        : 'UI change detected.');
    } else {
      console.log(`waiting ${settleMs / 1000}s for the console to ingest events…`);
      await handle.page.waitForTimeout(settleMs);
      await capture(handle.page, url, afterFile, cfg);
    }

    const result = diffImages(beforeFile, afterFile, outDir, cfg.diff);

    console.log('\n---- e2e verification result ----');
    console.log(`  changed pixels : ${result.changedPx} (${result.changedPct}%)`);
    console.log(`  changed regions: ${result.regions.length}`);
    for (const r of result.regions) {
      console.log(`    #${r.index}  x=${r.x} y=${r.y} w=${r.w} h=${r.h} (${r.count} px)`);
    }
    console.log(`  artifacts      : ${outDir}`);
    console.log('---------------------------------\n');

    const summary = {
      ts: new Date().toISOString(),
      ssh: { host: cfg.ssh.host, user: cfg.ssh.user },
      remoteCmd: cmdFile ? `<${cmdFile}` : cmd,
      url,
      changedPx: result.changedPx,
      changedPct: result.changedPct,
      regions: result.regions,
      files: { before: beforeFile, after: afterFile, diff: result.diffFile, marked: result.markedFile },
    };
    writeFileSync(join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
  } finally {
    await handle.close();
  }
}

// ---------------------------------------------------------------- main

async function main() {
  const a = parseArgs(process.argv.slice(2));
  const command = a._[0];
  if (!['login', 'session', 'baseline', 'run'].includes(command)) {
    console.log(`usage:
  node verify.mjs session  --config config.json      # keep a logged-in browser window open
  node verify.mjs login    --config config.json      # one-shot login (saves session profile)
  node verify.mjs baseline --config config.json [--url U] [--out DIR]
  node verify.mjs run      --config config.json --cmd "remote cmd" [options]

run options:
  --cmd "shell command"      command to execute on the SSH host
  --cmd-file script.sh       run a local script on the host via 'bash -s'
  --url U                    page to screenshot (overrides config page.url)
  --page NAME                named page from config page.urls (e.g. file|process|network)
  --out DIR                  artifact directory (default artifacts/run)
  --settle SECONDS           wait after remote command before AFTER capture
  --poll                     keep screenshotting until the UI changes
  --poll-interval SECONDS    poll cadence (default 5)
  --poll-max SECONDS         poll budget (default 120)
  --changed-pct PERCENT      poll goal, changed pixels % (default 0.5)

when browser.cdpPort is set (see config), run/baseline attach to the
running 'session' daemon instead of launching a fresh browser.

config is required (see config.example.json). SSH and Qualys creds can also
come from env: SSH_HOST SSH_USER SSH_PORT SSH_KEY QUALYS_USER QUALYS_PASS.`);
    process.exit(command ? 1 : 0);
  }

  const cfgPath = a.config;
  if (!cfgPath) die('--config config.json is required (see config.example.json)');
  loadDotEnv();
  const cfg = loadConfig(resolve(cfgPath));
  if (a['cdp-port']) cfg.browser.cdpPort = Number(a['cdp-port']);

  if (command === 'login') return cmdLogin(cfg);
  if (command === 'session') return cmdSession(cfg);
  if (command === 'baseline') return cmdBaseline(cfg, a);
  return cmdRun(cfg, a);
}

export { diffImages, findChangedRegions, loadPng };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.stack ?? err.message);
    process.exit(1);
  });
}