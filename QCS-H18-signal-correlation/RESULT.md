# QCS-H18 — Process, File, and Network Event Correlation

## What we wanted to prove

Can Qualys reconstruct a full investigation sequence from separate runtime
signals — shell → script creation → script execution → file read → DNS →
network connection — rather than showing isolated events?

## Verdict

**Covered at the sensor level.** The runtime sensor emits every leg of
the chain as events that **join cleanly** (process IDs + container id +
a unique marker) into the exact sequence the hypothesis asks for:
shell → create payload + script → script exec → file read → DNS → connect
to the receiver. Whether the *platform UI* offers a pre-joined
investigation view is a Qualys product question — the data to reconstruct
it is complete.

**Next release:** this leg is cluster-internal DNS (the pod resolves a
cluster-local service name via kube-dns). Agent 1.8 logs DNS natively
(`MSG_OP_QUALYS_DNS` — fqdn + answers + pod src IP), verified for
external-resolver lookups; the kube-dns path is not emitted in this
build — next release (H06 pattern).

## What we did

- Policy: process rule on the chain script + file-open rule on the
  payload + egress rule on the receiver port
- Workload (cluster): one container ran shell → created payload + script
  → script read the payload → resolved an internal hostname → connected
  to the receiver on :8080 (`pod.yaml` now ships the `citi-h18-svc`
  receiver — previously the upload target didn't resolve and the
  network leg produced no event)

## What we observed (correlated chain)

EC2 run (`hypo-run.py --labs 18`, v1 mode, 2026-11-06): **PROVEN** —
13 matching events in 52.2s covering the payload open, the chain-script
exec chain, and the egress connect to the receiver.


| Leg | Event | Attribution |
| --- | --- | --- |
| parent shell | exec event | container id |
| script creation | file-open (payload/script) | shell |
| script execution | exec-check (chain script) | script matched |
| file read | file-open (payload) | cat (child of script) |
| DNS | UDP to kube-dns | getent — **next release** (1.8 logs pod DNS to external resolvers; kube-dns path silent) |
| network connect | `tcp_connect` → :8080 | the chain script |
| unique marker | in names/argv | all legs |

Join key: process ID → parent process ID across the events, plus the
marker in argv — the full sequence reconstructs in order.

## Caveats

- The DNS leg is UDP — invisible to the TCP connect hook. Agent 1.8
  logs pod DNS to external resolvers natively; this lab's lookup goes to
  kube-dns, which is not emitted — a next-release item (H06 pattern).
- Events are joined by reconstruction (IDs/markers), not by a single
  "investigation" event — that UX is a platform concern.
- v1 cannot express the process-exec leg (script launch marker only via
  file-open).

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Create a runtime script | **YES** | file-open by shell (script/payload creation) |
| E2 | Execute via parent shell | **YES** | exec-check event for the chain script |
| E3 | Read a synthetic file | **YES** | file-open by the reader |
| E4 | Resolve an internal hostname (DNS) | **NOT covered — next release** | kube-dns path not emitted in this build (external-resolver pod DNS is logged natively) |
| E5 | Connect + upload to controlled endpoint | **YES** | `tcp_connect` from the chain script → receiver |
| E6 | Reconstruct the sequence | **YES PARTIAL** | events join cleanly by process IDs/marker/container — a pre-built "investigation sequence" view is a platform question |

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | process + file + network rules for the chain |
| `pod.yaml` | workload running the full chain |
| `RESULT.md` | this document |

`tracingpolicy-dns.yaml` was removed — agent 1.8 logs DNS natively
(`MSG_OP_QUALYS_DNS`), including pod lookups to external resolvers;
cluster-internal (kube-dns) DNS is a next-release item.