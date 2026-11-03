# Installing the citi-hypothesis-labs Skill (self-serve)

The **citi-hypothesis-labs** skill drives the Qualys runtime-detection
hypothesis lab workflow (policy → live agent → docker workload → event
verification → point-by-point coverage record). This file lets you
install the skill into any other Devin / agent environment without this
repo, and includes the full SKILL.md content below.

## What the skill does

- Scaffolds a self-contained lab (`citi-hypothesis/QCS-HNN-<slug>/`) with
  v2 + v1 policies, a `pod.yaml` workload, and a plain-language RESULT.md
- Enforces the point-by-point execution coverage rule (setup/execution
  points → evidence; gaps stated bluntly in RESULT + README)
- Documents the live e2e loop: agent → background `tetra getevents`
  capture → policy add → docker workload → grep events file
- Records CRS version support (1.45+ / 1.46+ / future release) per lab
- Captures eBPF-Agent events JSON into RESULT.md, the README coverage
  matrix, and the run log

## Prerequisites (target machine)

- Linux with root (`sudo`), docker, Go toolchain, and a built eBPF-Agent
  agent + `tetra` CLI (repo base `release/v1.6-1-q5`)
- BPF objects: `make ebpf-agent-bpf-local LOCAL_CLANG=1`
- The `citi-hypothesis/` package (setup.sh, teardown.sh, TEMPLATE,
  tools/v1convert) — unpack `citi-hypothesis.tar.gz` inside the repo root

## Installation

### 1. Install the skill for the current project

```bash
mkdir -p .devin/skills/citi-hypothesis-labs
cp SKILL-INSTALL.md .devin/skills/citi-hypothesis-labs/SKILL.md   # or use the block below
```

(Equivalent: paste the full SKILL.md content from the section below into
`.devin/skills/citi-hypothesis-labs/SKILL.md`.)

### 2. Install globally (any project, user-level)

```bash
mkdir -p ~/.config/devin/skills/citi-hypothesis-labs
# copy the SKILL.md content below into ~/.config/devin/skills/citi-hypothesis-labs/SKILL.md
```

### 3. Other agent flavors (manual copy)

- Claude Code: `.claude/skills/citi-hypothesis-labs/SKILL.md`
- Cursor: `.cursor/rules/` or the skills directory your setup uses
- Windsurf: `.windsurf/skills/citi-hypothesis-labs/SKILL.md`

### 4. Bring the supporting package

```bash
tar xzf citi-hypothesis.tar.gz     # citi-hypothesis/ + .devin/skills/citi-hypothesis-labs/
cd ebpf-agent
sudo citi-hypothesis/setup.sh      # builds agent+tetra, starts agent + capture
```

`tools/v1convert` (legacy qualys.com/v1 → TracingPolicy converter) and
`tools/miner-sim.yaml` ship inside `citi-hypothesis/tools/`.

## Verify the install

```bash
# from the agent: the skill should be discoverable, e.g.
#   skill list / search citi-hypothesis-labs
ls .devin/skills/citi-hypothesis-labs/SKILL.md
```

Then run a lab: `cp -r citi-hypothesis/TEMPLATE citi-hypothesis/QCS-HXX-<slug>`
and follow the skill flow.

---

## Full SKILL.md content

```markdown
# citi-hypothesis labs

Each hypothesis becomes a self-contained lab under `citi-hypothesis/<LAB>/`
with: `policy.yaml` (RuntimePolicy v2), `pod.yaml` (k8s/OpenShift workload
that generates the activity once applied), and `RESULT.md` (plain-language
hypothesis, commands, observed output, verdict).

## Environment

- Base branch: `release/v1.6-1-q5` (`setup.sh` warns otherwise)
- Bring up the lab environment once per session:
  `sudo citi-hypothesis/setup.sh` — builds `ebpf-agent`+`tetra` with
  `go build -mod=mod`, starts the agent on `:54321`, captures
  `tetra getevents -o json` to `/tmp/citi-labs/events.jsonl`
- Tear down with `sudo citi-hypothesis/teardown.sh`

## Per-hypothesis flow

1. `cp -r citi-hypothesis/TEMPLATE citi-hypothesis/QCS-HNN-<slug>` and fill
   in the policy + pod + hypothesis text.
2. **Break the hypothesis text into point-wise items FIRST** — separate
   "Required setup" points from "Execution flow" points. Every point gets
   an ID (`S1, S2, …` setup, `E1, E2, …` execution).
3. Build the `pod.yaml` + docker command so that **each execution point has
   at least one action that generates the evidence** for it. If a point
   needs no new action (e.g. it is a platform observation), say so in the
   RESULT rather than skipping it silently.
4. `./tetra tracingpolicy add <lab>/policy.yaml` — v2 is auto-translated to
   per-rule policies named `<policy>-v2-<rule-id>`.
5. Drive the activity with `docker run`/`docker exec` (exact command goes
   into RESULT.md); `sleep ~5` for delivery.
6. Inspect `/tmp/citi-labs/events.jsonl` — match `policy_name`,
   `process.binary`, `args[].file_arg.path`, `parent`, `docker` fields.
   This is the E2E loop: agent → background `tetra getevents` capture →
   policy apply → docker workload → grep the capture file for the events.
   A point is covered only when its evidence is IN THE FILE.
7. `./tetra tracingpolicy delete <policy> --all-rules`; write RESULT.md in
   plain, non-technical language (verdict up front).

## Execution-point coverage (mandatory, per lab)

- RESULT.md must contain a **"Point-by-point check" table**: one row per
  setup/execution point of the original hypothesis, with the evidence that
  covers it (event type + field) or **"Not covered"**.
- A point is "covered" only when the recorded event actually contains the
  asked-for data (e.g. "container identity" needs the `docker`/`pod`
  field on the event, not just a mention in prose).
- **Any "Not covered" point must ALSO appear in `citi-hypothesis/README.md`
  under a per-lab "Execution points not covered" line** — the README is the
  single place reviewers check coverage.
- **Every point also gets a row in the README "Execution coverage matrix"**
  (columns: Lab | Point | Task | Policy | How it worked) — append for every
  new lab, keep it in sync with the RESULT point table.
- **BE BLUNT about coverage.** If the policies cannot cover an execution
  step or the case, say so in plain words — "Cannot cover", "Not
  supported", "No policy can express this" — in the RESULT point table,
  the verdict, AND the README matrix row. Never soften or hedge a gap:
  no "mostly works", no "partially acceptable", no silent omission. A
  lab that hides a gap is worse than a lab that proves one.
- Platform-only legs (image scan, audit-log verdicts, sensor-health UI,
  admission/SCC verdicts) count as "Not covered by the runtime lab — see
  platform" and are listed in both places. Do not pretend they were tested.
- Negative controls (should NOT fire) are as important as positives: run
  one and record that it produced no event.

## RuntimePolicy v2 coverage (release/v1.6-1-q5)

- `type: file` — `fileOperation`: read, write, write-diff, create, delete,
  rename, open, metadata (chmod/chown/truncate), links
- `type: process` — `matchBinaries` on `security_bprm_check` (block kills
  before exec commits)
- `type: network` — `direction` egress|ingress|both
- `action` — `audit` → Post event; `block`/`kill` → SIGKILL the actor
- Operators: In/NotIn/Prefix/NotPrefix/Postfix/NotPostfix on
  matchFilePaths/matchBinaries
- Not supported by v2 (translator marks Not-applied): matchQLPs,
  containerSelector; network ingress block paths

## CRS version note (per lab)

- Add the CRS tier to the top of `pod.yaml`:
  `# CRS version support: <1.45+|1.46+|future release> — <why>`
- `1.45+` = RuntimePolicy v1 suffices; `1.46+` = v2 required; a leg that
  needs a raw Cilium TracingPolicy hook = future release. Sub-legs that
  differ from the primary tier are called out in the same comment.

## Fallback: raw Cilium TracingPolicy

If a hypothesis needs a hook v2 can't express (other syscalls, LSM hooks,
uprobes, tracepoints, custom args), ship `tracingpolicy.yaml`
(`apiVersion: cilium.io/v1alpha1`, see `TEMPLATE/tracingpolicy.yaml`) —
`tetra` applies it verbatim. Add a **"Future implementation"** section in
RESULT.md naming the v2 field that would be needed.

## Gotchas

- `matchFilePaths`/`matchBinaries` evaluate paths **as the container
  resolves them** — mount the workload path exactly where the policy
  expects (see QCS-H01 negative control).
- Path filters match the RESOLVED path — symlinks are followed before
  matching (`/var/run` → `/run`), so list both prefixes or use a Postfix
  on the stable tail (QCS-H09).
- `pkill -f "<pattern>"` can match the invoking shell's own command line
  and kill it — kill by PID/pidfile instead.
- `pod`/`namespace` event fields only populate under k8s; plain docker
  shows `docker` container id only.
- `action: block` = SIGKILL the process (exit 137), not a clean denial.
- `binary_properties` (setuid/caps/memfd+deleted execs) needs
  `--enable-process-cred`; pass `EBPF_AGENT_ARGS="--enable-process-cred"`
  to setup.sh. memfd execs can't be blocked via `matchBinaries` paths —
  Sigkill `sys_memfd_create` instead (QCS-H04).
- `tcp_connect` fires at SYN-send: refused/dropped connects look identical
  to successes (ret=0) — attempts are recorded, outcomes are not (H06/H07).
- matchPorts/matchBinaries are ignored on network block/ingress rules;
  matchDNS/matchFQDN only apply to egress block (connect4).
- v1 (legacy `qualys.com/v1`) policies: one CR per `base-policy`,
  `monitor-paths` are Prefix-only on resolved paths, all Post actions get
  a forced `rateLimit: 1m/global`, no process-exec base-policy — use
  `tools/v1convert` to emit the operator-identical TracingPolicy locally.
```

## Version history

- 2026-11-03 — added BE BLUNT coverage rule, CRS version notes, execution
  coverage matrix requirement, e2e-loop definition.
- 2026-11-02 — recreated after worktree cleanup (was preserved in git stash).
- 2026-10-29 — original skill (H01–H08 workflow, v2 coverage, raw TP fallback).
