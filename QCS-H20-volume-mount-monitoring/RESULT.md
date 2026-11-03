# QCS-H20 — Volume Mount Monitoring in Containers

## What we wanted to prove

Can a Tetragon/Cilium policy watch volume mounts — both the volumes a
container receives when it starts (`docker run -v`) and mounts a process
performs *inside* a running container — and report who did it, to what
target, with what filesystem, and whether it succeeded?

## Verdict

**Partially — and the split is sharp.** The policy (a raw `sys_mount`
kprobe) fully captures **every volume/filesystem mount the container
runtime performs at container start** — including the `-v` volume bind
mount, the overlay rootfs, proc/devpts/sysfs/cgroup/shm, and the
resolv.conf/hostname/hosts bind mounts — each with source, target,
filesystem type, flags and return value. But a `mount(2)` issued by a
process **inside a running container** (e.g. `mount -t tmpfs` in a
privileged container) produces **no event** in this build
(`release/v1.6-1-q5`) — even though the kernel-level kprobe fires for
those calls and other syscalls from the same process are fully traced.
RuntimePolicy v2 cannot express the mount syscall at all; its file rules
do, however, see reads inside mounted volumes.

## What we did

- **Policy 1 (raw Cilium TracingPolicy, `tracingpolicy.yaml`):** kprobe on
  `sys_mount` (`syscall: true`) capturing source, target, filesystem type,
  mount flags, and the return value (0 = success, negative errno = failure).
  Applied verbatim with `./tetra tracingpolicy add` (v2 cannot express
  syscall hooks — this is the documented fallback).
- **Policy 2 (RuntimePolicy v2, `policy.yaml`):** report every file read
  or create under `/mnt/citi-h20/` (the volume mount target).
- **Workloads (docker run):**
  - A: `docker run -v /tmp/citi-h20-data:/mnt/citi-h20 …` — volume mount
    at container start, then read/write inside the mounted volume
  - B: unprivileged in-container `mount -t tmpfs` (fails with EPERM)
  - C: `--cap-add SYS_ADMIN` in-container `mount -t tmpfs` (succeeds)
  - D: `--privileged` bind of host `/` into the container (succeeds)
  - E: host-side `mount -t tmpfs` (control)
- **Events:** grabbed live with `tetra getevents -o json` (agent capture
  in `/tmp/citi-labs/events.jsonl`).

## What we observed

| Case | sys_mount event? | What the record showed |
|---|---|---|
| A: `docker run -v` volume mount | **Yes** | bind mount `source=/tmp/citi-h20-data` → container (runc target fd), `fstype=bind`, `flags=20480 (MS_BIND\|MS_REC)`, `ret=0` — plus the full start sequence: overlay rootfs, proc, tmpfs, devpts, sysfs, cgroup2, mqueue, shm, resolv.conf, hostname, hosts, netns |
| A: file activity inside the mounted volume | **Yes** | v2 `vol-read` rule fired: `vfs_read` on `/mnt/citi-h20/seed.txt` and `/mnt/citi-h20/new.txt` by `/usr/bin/cat` (paths as the container resolves them) |
| B: unprivileged in-container mount | **No** | mount(2) executed (EPERM, rc=32) but no kprobe event |
| C: CAP_SYS_ADMIN in-container mount | **No** | mount succeeded (file written and read back) but no kprobe event |
| D: privileged bind of host `/` | **No** | mount succeeded but no kprobe event |
| E: host-side mount (control) | **Yes** | `source=tmpfs target=/tmp/citi-h20-hostmnt fstype=tmpfs flags=0 ret=0` |

All 71 `sys_mount` events carried `ret=0`; attempts that fail are recorded
the same way at the syscall level (retval = negative errno).

## What we verified while chasing the in-container gap

- A **kernel-level** kprobe on `__x64_sys_mount` (tracefs, manual) fires
  for the in-container `mount` call — the syscall really does run through
  `__x64_sys_mount` inside the container.
- The in-container mount process **is** present in Tetragon's execve map
  (nonzero ktime), and its `process_exec`/`process_exit` records appear.
- `sys_openat` and `vfs_read` kprobe events **do** get emitted for the
  same in-container process (the `mount` binary produced 8 openat events).
- Therefore the drop is inside Tetragon's generic-kprobe/tracepoint path,
  specific to syscall-hook events for processes inside running containers:
  `sys_mount` kprobe and `sys_enter_mount` tracepoint were both silent
  in-container; function kprobes (vfs_read, sys_openat) worked; a host
  process in a *fresh* mount namespace (`unshare -m` + mount) fired fine —
  the discriminator is the container cgroup, not the mount namespace.
- Docker container-id attribution is not populated in this environment
  (`docker: None`, `cgroup: None` even for in-container execs); pod/
  namespace fields only populate under k8s, per the lab gotchas.

## Agent flag experiments (does a namespace flag close the gap?)

Re-ran the full case set with the agent's namespace flags changed.
**Coverage is unchanged** — cases B/C/D are still silent in every
combination — but one flag fixes a real attribution bug:

| Flags (besides `--enable-process-cred`) | Cases B/C/D (in-container mount) | Case A/E events | Process attribution |
|---|---|---|---|
| defaults (`--enable-host-ns-filter=true`) | **silent** | yes | runtime mounts attributed to `/usr/lib/systemd/systemd` (wrong); host mount attributed to the `devin` wrapper |
| `--enable-host-ns-filter=false` | **silent** | yes (same 71 events) | runtime mounts correctly attributed to `/usr/bin/runc`; host mount correctly attributed to `/usr/bin/mount` |
| `--enable-host-ns-filter=false --enable-pod-ns-filter=false` | **silent** | yes | same correct attribution |
| `+ --enable-process-ns` | **silent** | yes | same |
| `--enable-qualys-sensors` | — | — | **agent fails to start** (`bpf_qualys_dnsr.o` load failure on this kernel) |

So `--enable-host-ns-filter` (default true) gates the namespace tracking
the agent uses to resolve who performed an event: with it off, the
container-start mounts are correctly attributed to runc and the host
mount to `mount(1)`. It does **not** change which mount(2) calls produce
events — the in-container gap remains in all configurations.

## Caveats for the field

- **In-container `mount(2)` is not visible via `sys_mount` in this build.**
  Defense-in-depth for that blind spot: (1) watch file activity in mounted
  paths with v2 file rules (works in-container), (2) the runtime-driven
  mounts at container start are fully visible, and (3) block the
  capability (`--cap-add SYS_ADMIN`) so in-container mounts fail anyway —
  the mount(1) attempt is then logged via `process_exec`.
- The v2 `create` rule (security_inode_create) did not match the
  `echo > file` create into the mounted volume in this test; the `read`
  rule matched reliably. Prefer read/open rules for mounted-volume
  visibility today.
- Volume mounts at container start are attributed to the runtime process
  (dockerd/runc/systemd), not to a "container" entity, because docker-id
  attribution is off in this environment.

## Future implementation

RuntimePolicy v2 needs a syscall rule type (e.g. `type: syscall` with a
`syscall: mount` field) so mount monitoring can be expressed in v2
without the raw Cilium TracingPolicy fallback. Separately, the
in-container syscall-hook event gap (sys_mount/sys_enter_mount silent for
processes in container cgroups while sys_openat/vfs_read work) should be
investigated in the generic-kprobe path of this fork — it is reproducible
and kernel-level instrumentation confirms the calls happen.

## Files in this lab

| File | Purpose |
|---|---|
| `tracingpolicy.yaml` | raw Cilium TracingPolicy — `sys_mount` kprobe audit (the mount-monitoring policy) |
| `policy.yaml` | RuntimePolicy v2 — file read/create inside the mounted volume |
| `pod.yaml` | k8s/OpenShift workload (hostPath volume + privileged tmpfs mount) |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
# 1. add the policies
./tetra tracingpolicy add citi-hypothesis/QCS-H20-volume-mount-monitoring/tracingpolicy.yaml
./tetra tracingpolicy add citi-hypothesis/QCS-H20-volume-mount-monitoring/policy.yaml

# 2. generate events
mkdir -p /tmp/citi-h20-data && echo hostseed > /tmp/citi-h20-data/seed.txt

# Case A — volume mount at container start + file activity in the volume
docker run --rm -v /tmp/citi-h20-data:/mnt/citi-h20 debian:stable-slim sh -c \
  'ls /mnt/citi-h20; cat /mnt/citi-h20/seed.txt; echo from-container > /mnt/citi-h20/new.txt; cat /mnt/citi-h20/new.txt'

# Case B — unprivileged in-container mount attempt (EPERM)
docker run --rm debian:stable-slim sh -c \
  'mkdir -p /mnt/citi-h20-tmp; mount -t tmpfs tmpfs /mnt/citi-h20-tmp; echo "mount rc=$?"'

# Case C — privileged in-container mount
docker run --rm --cap-add SYS_ADMIN debian:stable-slim sh -c \
  'mkdir -p /mnt/citi-h20-tmp; mount -t tmpfs tmpfs /mnt/citi-h20-tmp && echo proof > /mnt/citi-h20-tmp/p.txt && cat /mnt/citi-h20-tmp/p.txt && umount /mnt/citi-h20-tmp'

# Case D — privileged bind of host root into the container
docker run --rm --privileged debian:stable-slim sh -c \
  'mkdir -p /mnt/host-root; mount --bind / /mnt/host-root && ls /mnt/host-root/etc/hostname >/dev/null; umount /mnt/host-root'

# 3. grab the events (live capture already runs into /tmp/citi-labs/events.jsonl)
./tetra getevents -o json
# or, for the captured stream:
tail -f /tmp/citi-labs/events.jsonl | python3 -m json.tool

# 4. cleanup
./tetra tracingpolicy delete citi-h20-volume-mount-monitoring --all-rules
sudo citi-hypothesis/teardown.sh
```