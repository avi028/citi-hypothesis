# QCS-H15 — Suspicious Filename and File Integrity Monitoring

## What we wanted to prove

Qualys can watch selected filenames in a running container and record the
full lifecycle: create, modify, rename, read, delete — including
re-creation by a child process — with the filename, operation, process,
parent, and workload attached.

## Verdict

**Supported.** Every operation on the monitored files produced an event
with the resolved path, operation, binary, parent, and container id.
Recreation through a child `sh` was attributed to the child with the
parent shell on the event.

## What we did

- Policy: v2 file rules (`create`, `write`, `rename`, `delete`, `open`)
  on `/tmp/citi-h15/` — one policy match covers all filenames in the dir
- Workload: created `Login.jsp`, `Sql.java`, `package.json`; modified
  `Login.jsp`; renamed `Sql.java`; read `package.json`; deleted the
  renamed file; re-created `Login.jsp` via a child `sh -c`

## What we observed

| Operation | Hook | Process (parent) |
|---|---|---|
| create (3 files) | `security_inode_create` | bash |
| write (modify) | `vfs_write` | bash |
| rename | `security_path_rename` | mv (parent: bash) |
| read | `security_file_open` | cat (parent: bash) |
| delete | `security_path_unlink` | rm (parent: bash) |
| re-create via child | `security_file_open`/`vfs_write` | sh (parent: bash) |

Every event carried the resolved path (`/tmp/citi-h15/Login.jsp` …) and
container id; create/rename/delete hooks carry their target in dentry args.

## Alerting basis — filename vs policy match

Alerting is **policy-match based**: the rule watches the directory (prefix)
+ operation, and the *filename is data on the event*, not a per-filename
rule. A rule can of course be scoped tighter (e.g. `In` on exact paths)
to watch named files only. The event always answers "what file, what
operation, who did it".

## Caveats

- `monitor-paths`/`matchFilePaths` match the resolved path (symlinks
  followed — H09 lesson).
- Rename events report the source path in dentry args; the destination is
  also present on the hook's args.

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 FIM rules (create/write/rename/delete/open) on the monitored dir |
| `policy-v1.yaml` | v1 equivalents (5 base-policies) |
| `pod.yaml` | workload exercising the full file lifecycle incl. child re-creation |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H15-suspicious-filename/policy.yaml
docker run --rm debian:stable-slim bash -c '
  mkdir -p /tmp/citi-h15 && cd /tmp/citi-h15
  echo page-v1 > Login.jsp; echo class-v1 > Sql.java; echo "{\"name\":\"pkg\"}" > package.json
  echo page-v2 > Login.jsp            # modify
  mv Sql.java SqlOld.java             # rename
  cat package.json                    # read
  rm SqlOld.java                      # delete
  sh -c "echo page-v3 > /tmp/citi-h15/Login.jsp"   # child re-create'
```

Result: create/write/open/rename/delete events for all three filenames,
child re-creation attributed to `sh` under `bash`.