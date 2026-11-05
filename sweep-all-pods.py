#!/usr/bin/env python3
"""Sweep: apply every QCS-* lab's pod.yaml via kubectl, record the workload
status, then clean up. No policies are touched."""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("hyporun", "hypo-run.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def run(cmd, quiet=False):
    if not quiet:
        print("+ " + " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def workload_docs(lab):
    docs = [d for d in m.MiniYaml.parse_all(open(os.path.join(lab, "pod.yaml"),
                                                 encoding="utf-8", errors="replace").read())
            if isinstance(d, dict)]
    return docs


labs = sorted([d for d in os.listdir(".") if d.startswith("QCS-") and os.path.isdir(d)],
              key=m.lab_sort_key)
print("%-30s %-20s %-14s %s" % ("lab", "workload", "phase", "detail"))
for lab in labs:
    pod_path = os.path.join(lab, "pod.yaml")
    if not os.path.isfile(pod_path):
        print("%-30s %-20s %-14s %s" % (lab, "-", "-", "no pod.yaml"))
        continue
    try:
        docs = workload_docs(lab)
    except Exception as e:
        print("%-30s %-20s %-14s %s" % (lab, "-", "-", "parse fail: %s" % e))
        continue
    wl = m.parse_pod_yaml(pod_path)
    r = run(["kubectl", "apply", "-f", pod_path])
    if r.returncode != 0:
        print("%-30s %-20s %-14s %s" % (lab, wl.get("name") or "-", "-",
                                         "apply failed: " + (r.stderr or r.stdout).strip()[:80]))
        continue
    time.sleep(8)
    statuses = []
    for d in docs:
        if d.get("kind") not in ("Pod", "Job", "Deployment", "StatefulSet",
                                 "DaemonSet", "ReplicaSet", "CronJob"):
            continue
        name = (d.get("metadata") or {}).get("name") or ""
        ns = (d.get("metadata") or {}).get("namespace") or "default"
        r = run(["kubectl", "get", "pods", "-n", ns, "--no-headers",
                 "-o", "custom-columns=:metadata.name"], quiet=True)
        pnames = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith(name + "-")]
        if d.get("kind") == "Pod":
            pnames = [name]
        for pn in pnames:
            r2 = run(["kubectl", "get", "pod", pn, "-n", ns, "-o",
                      "jsonpath={.status.phase}|{.status.containerStatuses[0].state.waiting.reason}"],
                     quiet=True)
            phase, _, reason = r2.stdout.strip().partition("|")
            statuses.append("%s:%s%s" % (pn, phase, ("/" + reason) if reason else ""))
    print("%-30s %-20s %-14s %s" % (lab, wl.get("name") or "-",
                                     statuses[0].split(":")[1] if statuses else "-",
                                     "; ".join(statuses) if statuses else "no pods"))
    run(["kubectl", "delete", "-f", pod_path, "--ignore-not-found=true"], quiet=True)
    time.sleep(1)
print("\nsweep complete")