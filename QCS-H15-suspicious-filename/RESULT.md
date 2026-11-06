# QCS-H15 — Suspicious Filename and File Integrity Monitoring

## What we wanted to prove

Qualys can watch selected filenames in a running container and record the
full lifecycle: create, modify, rename, read, delete — including
re-creation by a child process — with the filename, operation, process,
parent, and workload attached.

## Verdict

**Covered.** Every operation on the monitored files produced an event
with the resolved path, operation, binary, parent, and container.
Recreation through a child shell was attributed to the child with the
parent shell on the event.

## What we did

- Policy: file rules (create/write/rename/delete/open) on the monitored
  directory — one policy match covers all filenames in the dir
- Workload (cluster): created `Login.jsp`, `Sql.java`, `package.json`;
  modified, renamed, read, deleted; re-created one via a child shell

## What we observed

| Operation | Hook | Process (parent) |
| --- | --- | --- |
| create (3 files) | create | bash |
| write (modify) | write | bash |
| rename | rename | mv (parent: bash) |
| read | open | cat (parent: bash) |
| delete | delete | rm (parent: bash) |
| re-create via child | open/write | sh (parent: bash) |

Every event carried the resolved path and container; create/rename/delete
carry their target in the hook args.

EC2 run (`hypo-run.py --labs 15`, v1 mode, 2026-11-06): **PROVEN** —
17 matching events in 52.3s. The workload spaces its ops 1s apart so
the v1 `1s`/pod rate limit records each create/write/rename/open/delete
(incl. the child-shell re-create) as its own event.

## Alerting basis — filename vs policy match

Alerting is **policy-match based**: the rule watches the directory +
operation, and the *filename is data on the event*, not a per-filename
rule. A rule can of course be scoped tighter (e.g. exact paths) to watch
named files only. The event always answers "what file, what operation,
who did it".

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Create monitored files | **YES** | create × 3 (`Login.jsp`, `Sql.java`, `package.json`) |
| E2 | Modify / rename / read / delete | **YES** | write, rename (mv), open (cat), delete (rm) |
| E3 | Recreate one file via child process | **YES** | child shell (parent bash) → open + write |
| E4 | Filename/path/op/timestamp/process/parent/workload | **YES** | resolved path + operation + process + parent + container on every event |
| E5 | Alerting basis: filename vs policy vs activity | **YES** | alerting is policy-match (dir + operation); the filename is event DATA, not the rule trigger |

**Not covered live:** none.

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | file rules on the monitored dir |
| `pod.yaml` | workload exercising the full file lifecycle incl. child re-creation |
| `RESULT.md` | this document |