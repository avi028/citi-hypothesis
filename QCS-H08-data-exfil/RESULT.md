# QCS-H08 — Controlled Data Transfer / Exfiltration Simulation

## What we wanted to prove

When a process reads a file and sends it out of the container, can Qualys
tie the read and the send to the same actor — including when the work is
done by a script created at runtime?

## Verdict

**Covered now: the correlation is exact.** The file-open event and the
outbound-connection event carry the same process and the same parent
chain, so "this process read this file and connected to that endpoint" is
a single joined story, not two guesses — including when the upload goes
through a just-created runtime script.

**Next release:** the DNS leg of the chain (UDP, via kube-dns). Agent
1.8 logs DNS natively (`MSG_OP_QUALYS_DNS`), verified for pod lookups
to external resolvers; the kube-dns path is not emitted in this build —
next release (H06/H18 pattern).

## What we did

- Policy: file-open audit on the payload file + egress audit on the
  receiver port
- Workload (cluster, self-contained): `pod.yaml` ships both ends — an
  httpd **receiver** (`citi-h08-receiver` service, `citi-h08-recv` ns) and
  the source pod, which uploads a synthetic file twice — directly, and
  again via a script written to `/tmp` at runtime. (Earlier revision had
  no receiver: curl failed at DNS before connect, so the egress leg
  produced no events.)

## What we observed

Upload 1 (direct): `curl` opened the payload file and connected to the
receiver — the file-open event and the `Network Activity` connect event
both carry the same process and parent chain (`/usr/bin/sh` script).

Upload 2 (runtime script): `sh` → `/tmp/citi-h08-upload.sh` → `curl` —
the sensor logged the script exec and then `curl` **with
`parent=/tmp/citi-h08-upload.sh`**: same file, same destination,
attributed *through the just-created script*.

k8s run on the EC2 lab (`hypo-run.py --labs 8`, v1 mode, 2026-11-06):
**PROVEN** — 37 matching events (file + network + exec chain) in 54.3s.

**Rate-limit caveat (verified live):** the v1 `net-tcp-open` policy
carries `rate-limit: "1s"` scoped to the pod — two connects in the same
second lose the second event. The workload therefore sleeps 2s between
the direct upload and the script upload; with that spacing each leg
produces its own `Network Activity` event (verified: `upload1` and
`upload2` both recorded).

## Privacy note (as designed)

The file-open record shows path + permissions only — **file contents are
never captured**. The connection record shows addresses and port, not the
uploaded bytes. Qualys attributes the transfer without exposing the data.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Read the synthetic file | **YES** | payload-open event by the reader |
| E2 | Upload to approved endpoint (direct) | **YES** | egress `tcp_connect` by `wget` |
| E3 | Repeat via newly created runtime script | **YES** | script exec → `wget` → open + connect again |
| E4 | Correlate file access / process exec / network | **YES** | open + connect on the same process; script chains as parent |
| E5 | Contents NOT captured | **YES** | events carry path + socket tuple only — no payload bytes |
| — | DNS leg of the chain | **NOT covered — next release** | kube-dns path not emitted; external-resolver pod DNS is logged natively |

**Not covered live:** the DNS leg (next release).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | payload-open file rule + egress audit rule |
| `pod.yaml` | receiver (httpd + svc in `citi-h08-recv`) + source pod with synthetic payload doing both uploads |
| `RESULT.md` | this document |