#!/usr/bin/env python3
"""Remove `runAsNonRoot: true` ONLY from test workload containers in lab
pod.yaml files. Restricted/negative-control pods (name contains 'restricted')
and all non-workload docs (Namespace/SA/Role/...) are preserved byte-for-byte.
The activity commands, images, volumes and policies are untouched."""
import os
import re

FAILING = ["QCS-H01-host-file-access", "QCS-H02-runtime-file-drift",
           "QCS-H03-process-lineage", "QCS-H04-fileless-exec",
           "QCS-H05-east-west-visibility", "QCS-H06-north-south",
           "QCS-H07-netpol-denied", "QCS-H08-data-exfil",
           "QCS-H09-service-account-token", "QCS-H10-cross-ns-rbac",
           "QCS-H12-vuln-image-in-use", "QCS-H13-image-lineage-drift",
           "QCS-H14-file-hash", "QCS-H15-suspicious-filename",
           "QCS-H16-policy-enforcement", "QCS-H17-deleted-pod-retention",
           "QCS-H18-signal-correlation", "QCS-H19-sensor-health"]

RANR = re.compile(r"^(\s*)runAsNonRoot:\s*true\s*$")
KIND_RE = re.compile(r"^kind:\s*(Pod|Job|Deployment|StatefulSet|DaemonSet|ReplicaSet|CronJob)\s*$")


def split_docs(lines):
    docs, cur = [], []
    for ln in lines:
        if ln.strip() == "---":
            if cur:
                docs.append(cur)
            cur = []
        else:
            cur.append(ln)
    if cur:
        docs.append(cur)
    return docs


def fix_file(path):
    text = open(path, encoding="utf-8").read()
    docs = split_docs(text.splitlines(keepends=True))
    changed = 0
    out_lines = []
    for idx, d in enumerate(docs):
        kinds = [KIND_RE.match(l).group(1) for l in d if KIND_RE.match(l)]
        restricted = any("restricted" in l.lower() for l in d if re.match(r"^\s*name:\s*", l))
        stripped = []
        removed = 0
        if kinds and not restricted:
            for l in d:
                if RANR.match(l):
                    removed += 1
                    continue
                stripped.append(l)
        else:
            stripped = list(d)
        if removed:
            changed += 1
        out_lines.extend(stripped)
        if idx < len(docs) - 1:
            out_lines.append("---\n")
    new = "".join(out_lines)
    if new != text:
        open(path, "w", encoding="utf-8", newline="").write(new)
    return changed


total = 0
for lab in FAILING:
    p = os.path.join(lab, "pod.yaml")
    if not os.path.isfile(p):
        continue
    n = fix_file(p)
    if n:
        total += n
        print("fixed %-32s (%d workload doc(s))" % (lab, n))
print("total workload docs fixed:", total)