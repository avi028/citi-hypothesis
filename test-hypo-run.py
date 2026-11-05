#!/usr/bin/env python3
"""Corner-case tests for hypo-run.py (run locally: python3 test-hypo-run.py)."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

spec = importlib.util.spec_from_file_location("hyporun", "hypo-run.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS  %s" % name)
    else:
        FAIL += 1
        print("FAIL  %s  %s" % (name, extra))


# ---- selection parser ------------------------------------------------------
def sel(text, mx):
    try:
        return m.parse_selection(text, mx)
    except m.SelectionError:
        return None

check("single", sel("4", 20) == [4])
check("range", sel("3-7", 20) == [3, 4, 5, 6, 7])
check("comma", sel("1,3,5", 20) == [1, 3, 5])
check("mixed", sel("1,3-5,7", 20) == [1, 3, 4, 5, 7])
check("all", sel("all", 20) == list(range(1, 21)))
check("ALL", sel("ALL", 20) == list(range(1, 21)))
check("a", sel("a", 20) == list(range(1, 21)))
check("blank=all", sel("", 20) == list(range(1, 21)))
check("natural union sorted", sel("10,2", 20) == [2, 10])
check("OOB", sel("21", 20) is None)
check("OOB range", sel("19-21", 20) is None)
check("reversed", sel("7-3", 20) is None)
check("zero", sel("0", 20) is None)
check("zero range", sel("0-2", 20) is None)
check("negative", sel("-1", 20) is None)
check("float", sel("3.5", 20) is None)
check("unicode digit", sel("\u0663", 20) is None)          # arabic three
check("stray space", sel("3 - 7", 20) is None)
check("en dash", sel("3\u20137", 20) is None)
check("em dash", sel("3\u20147", 20) is None)
check("duplicate", sel("2,2", 20) is None)
check("dup via range", sel("3-5,3", 20) is None)
check("non-numeric", sel("x", 20) is None)
check("space inside token", sel(" 3 ", 20) == [3])  # outer spaces tolerated (stripped)
check("max boundary", sel("20", 20) == [20])

# ---- event matching ----------------------------------------------------------
EV = json.dumps({
    "policy_name": "citi-h05-east-west-v2-east-west-egress",
    "metadata": {"uid": "abc-123"},
    "process": {"binary": "/usr/bin/curl"},
})
check("json policy_name match", m.event_matches(EV, ["citi-h05-east-west", "citi-h05-east-west-v2-east-west-egress"], ["east-west-egress"])[0] is True)
check("json dedupe key", m.event_matches(EV, ["citi-h05-east-west"], [])[1] == "abc-123")
EV2 = json.dumps({"metadata": {"correlation_uid": "audit-touch-cp"}, "process": {"name": "touch"}})
check("correlation_uid match", m.event_matches(EV2, ["proc-touch"], ["audit-touch-cp"])[0] is True)
EV3 = "raw text line with citi-h02-runtime-file-drift-v2-drift-create in it"
check("raw substring match", m.event_matches(EV3, ["citi-h02-runtime-file-drift"], [])[0] is True)
EV4 = '{"policy_name": "other-policy", "metadata": {"uid": "x"}}'
check("non-match", m.event_matches(EV4, ["citi-h02"], [])[0] is False)
check("malformed json still matcheable", m.event_matches("{not json with citi-h02 inside", ["citi-h02"], [])[0] is True)

# ---- Not-applied warnings -----------------------------------------------------
pol = {"text": "spec:\n  rules:\n  - name: r1\n    type: network\n    action: block\n    matchPorts:\n    - operator: In\n      values: [80]",
       "rules": [{"name": "r1", "id": "r1", "type": "network", "action": "block", "raw": '{"matchPorts": [80]}'}]}
warns = m.not_applied_warnings(pol, "install output: rule Not-applied")
check("not-applied warnings detected", len(warns) >= 2)

# ---- lab scanning with fake dirs ----------------------------------------------
tmp = tempfile.mkdtemp(prefix="hypo-test-")
try:
    os.makedirs(os.path.join(tmp, "QCS-H02-ok"))
    os.makedirs(os.path.join(tmp, "QCS-H10-ok"))
    os.makedirs(os.path.join(tmp, "QCS-H01-no-pod"))
    os.makedirs(os.path.join(tmp, "QCS-H03-bad-yaml"))
    os.makedirs(os.path.join(tmp, "NOTALAB"))
    for d, pol_txt, pod_txt in [
        ("QCS-H02-ok",
         "apiVersion: qualys.com/v2\nkind: RuntimePolicy\nmetadata:\n  name: citi-h02\nspec:\n  rules:\n  - name: r1\n    type: file\n    action: audit\n",
         "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: debian:stable-slim\n"),
        ("QCS-H10-ok",
         "apiVersion: qualys.com/v2\nkind: RuntimePolicy\nmetadata:\n  name: citi-h10\nspec:\n  rules:\n  - name: r1\n    type: process\n    action: audit\n",
         "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: busybox\n"),
    ]:
        with open(os.path.join(tmp, d, "policy-v2.yaml"), "w") as f:
            f.write(pol_txt)
        with open(os.path.join(tmp, d, "pod.yaml"), "w") as f:
            f.write(pod_txt)
        with open(os.path.join(tmp, d, "RESULT.md"), "w") as f:
            f.write("# T\n\n## Verdict\n\n**Supported** — yes\n")
    with open(os.path.join(tmp, "QCS-H03-bad-yaml", "policy-v2.yaml"), "w") as f:
        f.write(": : : : :\nnot: [valid\n")
    with open(os.path.join(tmp, "QCS-H03-bad-yaml", "pod.yaml"), "w") as f:
        f.write("kind: Pod\n")
    # v1-mode lab: CRS 1.45+ with only policy-v1.yaml -> mode v1 (fallback)
    os.makedirs(os.path.join(tmp, "QCS-H21-v1only"))
    with open(os.path.join(tmp, "QCS-H21-v1only", "policy-v1.yaml"), "w") as f:
        f.write("apiVersion: qualys.com/v1\nkind: RuntimePolicy\nmetadata:\n  name: citi-h21-v1\nspec:\n  base-policy: file-read\n  action: audit\n")
    with open(os.path.join(tmp, "QCS-H21-v1only", "pod.yaml"), "w") as f:
        f.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: busybox\n")
    with open(os.path.join(tmp, "QCS-H21-v1only", "RESULT.md"), "w") as f:
        f.write("# T\n\n## Verdict\n\n**Supported** - yes\n")
    runnable, not_runnable = m.scan_labs(tmp)
    names = [l["name"] for l in runnable]
    check("natural order H02 before H10", names == ["QCS-H02-ok", "QCS-H10-ok", "QCS-H21-v1only"])
    check("not-runnable listed", [l["name"] for l in not_runnable] == ["QCS-H01-no-pod", "QCS-H03-bad-yaml"])
    reasons = {l["name"]: l["reason"] for l in not_runnable}
    check("reason: missing pod.yaml", "missing pod.yaml" in reasons.get("QCS-H01-no-pod", ""))
    check("reason: malformed yaml", "malformed" in reasons.get("QCS-H03-bad-yaml", "").lower() or "yaml" in reasons.get("QCS-H03-bad-yaml", "").lower())
    check("verdict parsed", runnable[0]["verdict"].startswith("Supported"))
    check("policy name parsed", runnable[0]["policy"]["name"] == "citi-h02")
    check("pod image parsed", runnable[0]["pod"]["image"] == "debian:stable-slim")

    # no runnable labs -> exit 1 via main? (unit: scan returns empty)
    os.makedirs(os.path.join(tmp, "QCS-H05-nothing"), exist_ok=True)
    r2, nr2 = m.scan_labs(tmp)
    check("runnable excludes incomplete", all("QCS-H05-nothing" != l["name"] for l in r2))
    v1labs = [l for l in runnable if l["name"] == "QCS-H21-v1only"]
    check("v1 mode selected by CRS", v1labs and v1labs[0]["mode"] == "v1" and v1labs[0]["policy_path"].endswith("policy-v1.yaml"))
    check("v1 base_policy parsed", v1labs and v1labs[0]["policy"]["base_policy"] == "file-read")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# ---- atomic report -------------------------------------------------------------
tmp2 = tempfile.mkdtemp(prefix="hypo-rep-")
try:
    rep = {"a": 1, "labs": [{"x": "y"}], "started_at": "t", "finished_at": "t",
           "duration_s": 1, "exit_reason": "test", "env": {}, "left_installed": []}
    pth = os.path.join(tmp2, "report.json")
    m.write_report_atomic(rep, pth)
    check("report atomic write", json.load(open(pth))["a"] == 1)
    m.write_md_atomic(rep, os.path.join(tmp2, "report.md"))
    check("md report written", os.path.isfile(os.path.join(tmp2, "report.md")))
finally:
    shutil.rmtree(tmp2, ignore_errors=True)

# ---- exit codes (subprocess) ----------------------------------------------------
import subprocess
def rc(args, env=None):
    e = dict(os.environ)
    e["RUN_DIR"] = tempfile.mkdtemp(prefix="hypo-rc-")
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, "hypo-run.py"] + args, capture_output=True, text=True, env=e)
    return p.returncode, p.stdout + p.stderr

c, out = rc(["--labs", "7-3", "--dry-run"])
check("bad --labs -> exit 2", c == 2, out[-200:])
c, out = rc(["--labs", "0", "--dry-run"])
check("zero --labs -> exit 2", c == 2)
c, out = rc(["--dry-run", "--labs-dir", tempfile.mkdtemp(prefix="hypo-empty-")])
check("empty labs dir -> exit 1", c == 1, out[-200:])

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)