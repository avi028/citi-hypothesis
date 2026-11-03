# e2e-verify — UI verification for citi-hypothesis labs

Prove a lab end-to-end: drive the workload on the Tetragon host over SSH,
watch the Qualys console react, and get pixel-exact evidence of the UI change.

```
┌──────────────┐   ssh (key auth)   ┌────────────────────┐
│  this laptop │ ─────────────────▶ │ Tetragon host      │
│  verify.mjs  │   lab commands     │  setup / policy /  │
│              │ ◀───────────────── │  workload / events │
│  playwright  │   console UI       └────────────────────┘
│  (msedge)    │ ─────────────────▶ Qualys console
└──────────────┘   before/after screenshots
```

## Install

```bash
cd citi-hypothesis/tools/e2e-verify
npm install
# browsers: uses your installed Edge/Chrome by default (browser.channel).
# If neither exists, install the bundled chromium:
npx playwright install chromium
```

## Configure

```bash
cp config.example.json config.json   # edit ssh host/user/key, page url
```

Credentials never go in the config file — use env vars:

```bash
set SSH_HOST=10.0.0.5        # or put in config.json
set SSH_USER=root
set SSH_KEY=C:/Users/you/.ssh/id_ed25519
set QUALYS_USER=you@corp.com
set QUALYS_PASS=********
```

SSH uses key auth (`BatchMode=yes`); make sure your key/agent works:

```bash
ssh -i C:/Users/you/.ssh/id_ed25519 root@10.0.0.5 "echo ok"
```

## Keep a session open (recommended)

Qualys doesn't reliably keep its session across browser restarts, so the
tool keeps one logged-in browser window open and attaches to it over CDP.
Start it once:

```bash
node verify.mjs session --config config.json
# -> opens Edge, logs in (creds from .env), stays open on port 9222
```

Keep that window open. Every `run`/`baseline` then attaches to it — the
session never needs re-login, and you can watch the console react live.

- Ctrl+C in that terminal closes the session cleanly.
- No daemon running? `run` falls back to launching a browser and
  auto-logging-in (slower, but self-contained).
- If the Qualys session expires mid-way, the next `run` detects the login
  page and re-authenticates automatically.

## One-shot login (optional)

Logs in and closes the browser, saving the session profile:

```bash
node verify.mjs login --config config.json
```

## Verify a lab

The flow for e.g. QCS-H02 (file drift):

```bash
node verify.mjs run --config config.json --out artifacts/QCS-H02 ^
  --cmd "cd /root/tetragon && ./tetra tracingpolicy add citi-hypothesis/QCS-H02-runtime-file-drift/policy.yaml && docker run --rm debian:stable-slim sh -c 'mkdir -p /tmp/citi-h02 && echo x > /tmp/citi-h02/a' && sleep 5 && tail -n 3 /tmp/citi-labs/events.jsonl"
```

Long command chains are easier as a script — copied to the host once or read
from a local file (runs via `bash -s`):

```bash
node verify.mjs run --config config.json --out artifacts/QCS-H02 --cmd-file ../scripts/QCS-H02.sh
```

Or wait until the console actually shows the change:

```bash
node verify.mjs run --config config.json --out artifacts/QCS-H02 --cmd-file ../scripts/QCS-H02.sh --poll --changed-pct 0.5
```

## Artifacts (per `--out` dir)

| file             | meaning                                                        |
|------------------|----------------------------------------------------------------|
| `before.png`     | console before the remote command                              |
| `after.png`      | console after the remote command                               |
| `diff.png`       | pixelmatch overlay — red pixels are changed                    |
| `diff-marked.png`| `after.png` with changed regions boxed and numbered            |
| `summary.json`   | machine-readable result (changed %, region boxes, command ran) |

`diff-marked.png` is the evidence artifact: each numbered box is one UI
region that changed in response to the server-side action.

## Tips

- Same viewport + `fullPage` setting for both captures or the diff errors out.
- Console ingest lag varies; bump `--settle` or use `--poll`.
- `baseline` captures a reference frame without running anything.
- `--cmd-file` scripts run with `bash -s` on the host — use LF line endings.
- Clean up policies afterwards (`./tetra tracingpolicy delete <policy> --all-rules`)
  so `after` only shows the lab's own events.

## Testing the harness itself (no SSH / no console needed)

`selftest.mjs` validates the diff pipeline on synthetic images:

```bash
node selftest.mjs
```

For a full `run`-flow dry-run: `smoke-server.mjs` serves a page that changes on
every request, `smoke-ssh.mjs` fakes the remote command, and `SSH_BIN` swaps out
the real ssh:

```bash
node smoke-server.mjs &          # http://127.0.0.1:8989
SSH_BIN="node smoke-ssh.mjs" node verify.mjs run \
  --config smoke-config.json --cmd "true" --url http://127.0.0.1:8989 \
  --out artifacts/_smoke --poll --poll-interval 1 --poll-max 8 --changed-pct 0.2
```