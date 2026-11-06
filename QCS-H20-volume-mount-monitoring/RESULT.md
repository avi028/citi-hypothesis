# QCS-H20 — Volume Mount Monitoring in Containers

## What we wanted to prove

Can a policy watch volume mounts — both the volumes a container receives
when it starts and mounts a process performs *inside* a running container
— and report who did it, to what target, with what filesystem, and
whether it succeeded?

## Verdict

**Partial — and the split is sharp.**

**Covered now:** file activity **inside mounted volumes** — the file rules
see reads/creates under the mount target with full attribution.

**Next release:** the **mount syscall monitoring itself** (every
volume/filesystem mount the container runtime performs at container
start, and mounts issued inside a running container) needed a raw
`sys_mount` kprobe that RuntimePolicy v2 cannot express. That raw
TracingPolicy has been **removed from the lab**; a future v2 `syscall`
rule type is the planned path. Note: in this build, mounts issued inside
a running container produced no event even via the raw hook — that gap is
documented below and is also a next-release item.

## What we did

- Policy 1 (raw `sys_mount` kprobe, `tracingpolicy.yaml`): captured every
  mount with source, target, filesystem type, flags, and return value —
  **removed, next release**
- Policy 2 (v2 file rules): report file reads/creates under the volume
  mount target
- Workloads: a volume mounted at container start with file activity
  inside; in-container mount attempts (unprivileged and privileged);
  privileged bind of host `/`; host-side mount (control)

## What we observed

| Case | Mount event? | File activity in the volume? |
| --- | --- | --- |
| Volume mounted at container start | Yes (raw hook — next release) | Yes — v2 file rules (reads under the mount target) |
| Unprivileged in-container mount | No (gap) | — |
| CAP_SYS_ADMIN in-container mount | No (gap) | — |
| Privileged bind of host `/` | No (gap) | — |
| Host-side mount (control) | Yes (raw hook) | — |

## Caveats for the field

- **In-container `mount(2)` was not visible via the raw hook in this
  build** — while kernel-level instrumentation confirms the calls happen
  and other syscalls from the same process are traced. Defense-in-depth
  for that blind spot: (1) watch file activity in mounted paths with v2
  file rules (works in-container), (2) the mounts at container start are
  fully visible, and (3) block the capability so in-container mounts fail
  anyway — the attempt is then logged via the process exec stream.
- Prefer read/open rules for mounted-volume visibility today.

## Future implementation

RuntimePolicy v2 needs a syscall rule type (e.g. `type: syscall` with a
`syscall: mount` field) so mount monitoring can be expressed in v2
without the raw TracingPolicy fallback — next release. Separately, the
in-container syscall-hook event gap should be investigated in the
generic-kprobe path of this fork.

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v2.yaml` | v2 file rules — reads/creates inside the mounted volume |
| `pod.yaml` | workload (hostPath volume + privileged mount) |
| `RESULT.md` | this document |

`tracingpolicy.yaml` (raw `sys_mount` kprobe) was removed — mount syscall
monitoring is a next-release item.
