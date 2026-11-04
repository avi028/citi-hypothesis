#!/usr/bin/env python3
"""Sweep: apply every QCS-* lab's pod.yaml via hypo-run's k8s client, record
the workload status, then clean up. No policies are touched."""
import importlib.util
import os
import time

spec = importlib.util.spec_from_file_location("hyporun", "hypo-run.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

k8s = m.K8s()


def workload_pod_names(doc):
    kind = doc.get("kind") or ""
    name = (doc.get("metadata") or {}).get("name") or ""
    ns = (doc.get("metadata") or {}).get("namespace") or k8s.namespace_default
    if kind == "Pod":
        return [(name, ns)]
    # Job/Deployment/... -> pods are <name>-<hash>
    pods = k8s.list_pods(namespace=ns, name_prefix=name + "-")
    return [(p, ns) for p in pods] or [(name + "-?", ns)]


labs = sorted([d for d in os.listdir(".") if d.startswith("QCS-") and os.path.isdir(d)],
              key=m.lab_sort_key)
print("%-30s %-20s %-14s %s" % ("lab", "workload", "phase", "detail"))
for lab in labs:
    pod_path = os.path.join(lab, "pod.yaml")
    if not os.path.isfile(pod_path):
        print("%-30s %-20s %-14s %s" % (lab, "-", "-", "no pod.yaml"))
        continue
    try:
        docs = [d for d in m.MiniYaml.parse_all(open(pod_path, encoding="utf-8", errors="replace").read())
                if isinstance(d, dict)]
    except Exception as e:
        print("%-30s %-20s %-14s %s" % (lab, "-", "-", "parse fail: %s" % e))
        continue
    wl = m.parse_pod_yaml(pod_path)
    applied = 0
    fails = []
    for d in docs:
        kind = d.get("kind") or ""
        name = (d.get("metadata") or {}).get("name") or ""
        ns = (d.get("metadata") or {}).get("namespace")
        if not kind or not name:
            continue
        try:
            st, body = k8s.apply_object(d)
        except Exception as e:
            fails.append("%s/%s:%s" % (kind, name, str(e)[:40]))
            continue
        if st in (200, 201):
            applied += 1
        else:
            fails.append("%s/%s=%d" % (kind, name, st))
    if not applied:
        print("%-30s %-20s %-14s %s" % (lab, wl.get("name") or "-", "-",
                                         "apply failed: " + "; ".join(fails)))
        continue
    # wait briefly for the workload to reach a terminal-ish state
    time.sleep(8)
    wdocs = [d for d in docs if d.get("kind") in ("Pod", "Job", "Deployment",
                                                  "StatefulSet", "DaemonSet", "ReplicaSet", "CronJob")]
    statuses = []
    for d in wdocs:
        for pname, pns in workload_pod_names(d):
            try:
                phase, reason = k8s.pod_status(pname, pns)
                statuses.append("%s:%s%s" % (pname, phase, ("/" + reason) if reason else ""))
            except Exception as e:
                statuses.append("%s:ERR(%s)" % (pname, str(e)[:30]))
    detail = "; ".join(fails) or ("; ".join(statuses) if statuses else "no workload pods")
    print("%-30s %-20s %-14s %s" % (lab, wl.get("name") or "-",
                                     statuses[0].split(":")[1] if statuses else "-", detail))
    # cleanup: delete in reverse
    for d in reversed(docs):
        kind = d.get("kind") or ""
        name = (d.get("metadata") or {}).get("name") or ""
        ns = (d.get("metadata") or {}).get("namespace")
        if not kind or not name:
            continue
        try:
            k8s.delete_object(kind, name, ns)
        except Exception:
            pass
    time.sleep(1)
print("\nsweep complete")