#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hypo-run — run citi-hypothesis labs end-to-end on a live Qualys ebpf-agent host.

USAGE
-----
    sudo python3 hypo-run.py [options]
    python3 hypo-run.py --dry-run
    python3 hypo-run.py --labs 1,3-5,7          # non-interactive selection

PHASES
    1. preflight  root, docker, go, python3, binaries, agent :54321, capture
                  growth, dir writability, env facts, agent flags, git branch,
                  disk space (live [OK]/[FAIL]/[WARN] report)
    2. selection  numbered labs; index / range / comma-list / all / blank;
                  strict validation, fixed natural-order indices
    3. execution  per lab: briefing -> install policy -> apply pod -> settle
                  -> evidence grep -> verdict -> cleanup (sequential)
    4. summary    consolidated report (json + md, written atomically)

OPTIONS
    --labs-dir DIR        lab directory (default: dir of this script)
    --events-file FILE    capture file (default: $RUN_DIR/events.jsonl)
    --log-file FILE       tee terminal output to FILE
    --dry-run             preflight + plan only, zero side effects
    --verbose / --debug   echo every command and its output
    --yes / --no-prompt   no interactive confirmation
    --fail-fast           abort the whole run on the first lab failure
    --keep                do not delete policy/pod after each lab
    --no-sudo             allow running as non-root (warned)
    --timeout-cmd SECS    per-command timeout (default 30)
    --timeout-poll SECS   policy-install poll budget (default 60)
    --settle SECS         wait after workload activity (default 5)
    --max-log-bytes N     events tail window (default 20971520)
    --max-events N        max evidence snippets printed (default 20)
    --labs SELECTION      selection string for CI (e.g. 1,3-5 or all)
    --backend auto|k8s|operator
                          execution backend; auto detects a reachable cluster
                          (k8s API, no kubectl needed) else the standalone
                          ebpf-operator flow
    --policy-mode v1|v2|auto
                          policy form to apply; default v1 (v2 has the
                          process/exec rules; auto picks by CRS version)
    --version             print version and exit

ENVIRONMENT (all flags also settable via env)
    HYPO_RUN_* mirrors every option above (e.g. HYPO_RUN_LABS_DIR).
    RUN_DIR, EBPF_AGENT, EBPF_OPERATOR, BPF_LIB are honored for setup.sh
    compatibility. Base branch check uses BASE_BRANCH (default
    release/v1.6-1-q5).

EXIT CODES
    0   all labs done
    1   preflight / environment failure
    2   usage error
    130 interrupted (SIGINT/SIGTERM, EOF at a prompt)

## Design decisions
-------------------
1. Stdlib + PyYAML (python3-yaml, shipped with the distro). Missing PyYAML
   fails fast with an install hint; we never pip-install on the box.
2. Subprocess discipline: every child is started in its own session
   (setsid) so we can kill the entire process group on timeout or
   interrupt — and we only ever kill children we spawned.
3. Evidence attribution: each lab's policy name is unique to the lab, so
   filtering the event window by policy name (base name and the translated
   "<policy>-v2-<rule-id>" names) cannot attribute a previous lab's events.
   Event timestamps are used as a secondary window when parseable; the tail
   of the capture is read only up to --max-log-bytes.
3b. v1 process-visibility evidence: v1 has no process-exec base-policy, so a
   v1 process-lab verdict matched on the v1 policy name alone can ride on
   operator lifecycle lines instead of detection payloads. In v1 mode the
   evidence grep additionally matches activity tokens extracted from pod.yaml
   and the v1 policy (runtime script paths, lab markers, monitored binaries)
   against the base-sensor policy-free process_exec stream, and the report
   distinguishes policy-name/rule-id hits from activity/process_exec hits.
4. "Policy installed" = the add command exited 0 AND the translated policy
   appears in `tracingpolicy list` (polled up to --timeout-poll). An
   already-installed policy is deleted then re-added (deterministic).
5. Verdicts: PROVEN (evidence count > 0), NOT-PROVEN (zero matches is a
   first-class result), SKIPPED (install failed/timed out), ABORTED
   (interrupted mid-lab). A NOT-PROVEN verdict is a valid result, never a
   crash.
6. Report files are written to a temp file and os.replace()d into place so
   a kill -9 mid-write cannot corrupt them. The report is written exactly
   once (idempotent handler flag).
7. Second Ctrl+C within 2s exits immediately (os._exit(130)) without a
   report, per spec. The first Ctrl+C records the interruption, kills the
   running child group, and lets the run unwind through the report path.
8. Interrupted during a background policy install: the install job is
   killed but installed policies are LEFT IN PLACE and listed as
   "left installed" in the report (never raced with a delete).
9. No TTY: no interactive prompts (selection falls back to --labs or
   "all"), no ANSI anywhere (we emit plain ASCII), command output decoded
   with errors="replace". Output width falls back to 80.
10. docker fallback: when kubectl is absent or the cluster is unreachable,
    the tool falls back to running the lab's pod image via docker (parsed
    from pod.yaml); this is weaker evidence and is flagged as such.
11. Single instance: fcntl.flock on $RUN_DIR/hypo-run.lock (O_EXCL
    fallback elsewhere); a concurrent run fails fast.
12. k8s backend (default when a cluster answers): uses `kubectl` for
    apply/delete of policy.yaml and pod.yaml manifests, `kubectl get
    runtimepolicy -o jsonpath` for the approval gate (state=Applied) and
    Not-applied rule states, and `kubectl exec ... cat <logfile>` /
    `kubectl logs` for evidence. Parsing, selection, gating and verdicts
    stay in-script. The sensor SIGKILLs `cat` of its own logs (exit 137), so
    the evidence path falls back to `kubectl logs`, which carries the event
    payloads.
"""

import argparse
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from datetime import datetime
from types import SimpleNamespace

__version__ = "1.6.0"

# --------------------------------------------------------------------------
# constants / defaults
# --------------------------------------------------------------------------

BASE_BRANCH_DEFAULT = "release/v1.6-1-q5"
RUN_DIR_DEFAULT = "/tmp/citi-labs"
DEFAULTS = {
    "labs_dir": None,          # None -> script dir
    "events_file": None,       # None -> $RUN_DIR/events.jsonl
    "log_file": None,
    "dry_run": False,
    "debug": False,
    "yes": False,
    "fail_fast": False,
    "keep": False,
    "no_sudo": False,
    "timeout_cmd": 30,
    "timeout_poll": 60,
    "settle": 5,
    "max_log_bytes": 20 * 1024 * 1024,
    "max_events": 20,
    "labs": None,
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LINE_WIDTH = 160
EVIDENCE_CAP = 20

# --------------------------------------------------------------------------
# global state / signals
# --------------------------------------------------------------------------

INTERRUPTED = {"flag": False, "t0": 0.0, "reported": False}
CURRENT_PROC = None  # the child process we may need to kill on interrupt
LOCK_FD = None


def interrupted():
    return INTERRUPTED["flag"]


def on_signal(signum, frame):
    now = time.time()
    if INTERRUPTED["flag"] and (now - INTERRUPTED["t0"]) < 2.0:
        # second ctrl+c: immediate exit, no report
        os._exit(130)
    if not INTERRUPTED["flag"]:
        INTERRUPTED["t0"] = now
        INTERRUPTED["flag"] = True
        log("")
        log("[WARN] interrupt received — finishing current step, then writing report")
        log("       (press Ctrl+C again within 2s to exit immediately)")
    if CURRENT_PROC is not None:
        try:
            kill_group(CURRENT_PROC)
        except Exception:
            pass


class Abort(Exception):
    """Raised on EOF-at-prompt / user abort — same path as Ctrl+C."""


# --------------------------------------------------------------------------
# output helpers (plain ASCII, no colors; tee to log file)
# --------------------------------------------------------------------------

LOG_FH = None


def _ascii(s):
    """Guarantee plain-ASCII output (spec: plain ASCII, no emojis)."""
    s = ANSI_RE.sub("", str(s))
    s = (s.replace("\u2014", "-").replace("\u2013", "-").replace("\u2026", "...")
           .replace("\u201c", '"').replace("\u201d", '"')
           .replace("\u2018", "'").replace("\u2019", "'")
           .replace("\u00b7", "-").replace("\u2550", "=")
           .replace("\u2588", "|").replace("\u25b6", ">").replace("\u00bb", ">"))
    return s.encode("ascii", errors="replace").decode("ascii")


def log(msg=""):
    line = _ascii(msg)
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    if LOG_FH is not None:
        try:
            LOG_FH.write(line + "\n")
            LOG_FH.flush()
        except Exception:
            pass


def logerr(msg):
    line = _ascii(msg)
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    if LOG_FH is not None:
        try:
            LOG_FH.write(line + "\n")
            LOG_FH.flush()
        except Exception:
            pass


def has_tty():
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def prompt(msg, default=None):
    """Interactive prompt. EOF -> Abort (same path as Ctrl+C)."""
    if not has_tty():
        if default is not None:
            return default
        raise Abort()
    try:
        val = input(msg)
    except EOFError:
        raise Abort()
    except KeyboardInterrupt:
        raise Abort()
    if default is not None and val.strip() == "":
        return default
    return val


# --------------------------------------------------------------------------
# subprocess helpers
# --------------------------------------------------------------------------

def decode(data):
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def kill_group(proc):
    if proc is None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run(cmd, timeout=None, check=False, input_data=None, cwd=None, quiet=False):
    """Run an external command. Returns (rc, stdout_str, stderr_str).

    Child is placed in its own session so the whole group can be killed on
    timeout/interrupt. Benign non-zero exits are the caller's business;
    `check` only raises for our own usage errors.
    """
    global CURRENT_PROC
    timeout = timeout if timeout is not None else CFG.timeout_cmd
    if CFG.debug and not quiet:
        log("+ " + " ".join(str(c) for c in cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            cwd=cwd,
            start_new_session=os.name == "posix",
        )
    except FileNotFoundError:
        return (127, "", "command not found: %s" % cmd[0])
    CURRENT_PROC = proc
    try:
        out, err = proc.communicate(input=input_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(proc)
        out, err = proc.communicate()
        return (124, decode(out), decode(err))
    finally:
        CURRENT_PROC = None
    return (proc.returncode, decode(out), decode(err))


def stream_start(cmd, cwd=None):
    """Start a background command; returns the Popen (group-killable)."""
    global CURRENT_PROC
    if CFG.debug:
        log("+ (bg) " + " ".join(str(c) for c in cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            start_new_session=os.name == "posix",
        )
    except FileNotFoundError:
        return None
    CURRENT_PROC = proc
    return proc


def stream_finish(proc, timeout=None):
    """Wait for a background command; returns (rc, out, err)."""
    global CURRENT_PROC
    timeout = timeout if timeout is not None else CFG.timeout_cmd
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(proc)
        out, err = proc.communicate()
        rc = 124
    else:
        rc = proc.returncode
    finally:
        CURRENT_PROC = None
    return (rc, decode(out), decode(err))


def trim_token(tok, limit=60):
    tok = tok.strip()
    if len(tok) > limit:
        return tok[: limit - 3] + "..."
    return tok


def trim_line(line, width=None):
    width = width or (shutil.get_terminal_size((80, 24)).columns if has_tty() else LINE_WIDTH)
    width = max(40, min(width, LINE_WIDTH))
    line = re.sub(r"\s+", " ", line).strip()
    if len(line) > width:
        return line[: width - 3] + "..."
    return line


def sleep_check(seconds):
    """Sleep in small chunks so Ctrl+C is noticed quickly."""
    end = time.time() + seconds
    while time.time() < end and not interrupted():
        time.sleep(min(0.25, end - time.time()))


# --------------------------------------------------------------------------
# lock (single instance)
# --------------------------------------------------------------------------

def acquire_lock(run_dir):
    global LOCK_FD
    try:
        os.makedirs(run_dir, exist_ok=True)
    except OSError:
        pass
    lock_path = os.path.join(run_dir, "hypo-run.lock")
    if os.name == "posix":
        try:
            import fcntl
        except ImportError:
            return None
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError:
            return None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return None
        os.truncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        LOCK_FD = fd
        return fd
    # non-posix fallback: exclusive create
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o644)
        os.write(fd, str(os.getpid()).encode())
        LOCK_FD = fd
        return fd
    except OSError:
        return None


def release_lock():
    global LOCK_FD
    if LOCK_FD is not None:
        try:
            os.close(LOCK_FD)
        except OSError:
            pass
        LOCK_FD = None
    if os.name != "posix" and CFG:
        try:
            os.unlink(os.path.join(CFG.run_dir, "hypo-run.lock"))
        except OSError:
            pass


# --------------------------------------------------------------------------
# YAML: PyYAML (python3-yaml, present on Ubuntu/RHEL). Strict - a malformed
# manifest raises, and scan_labs marks that lab not-runnable with the reason.
# kubectl itself reads the files for apply/delete; we only extract names,
# rule ids and workload refs.
# --------------------------------------------------------------------------

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

YAML_HINT = "PyYAML is required: apt install python3-yaml (or dnf install python3-pyyaml)"


def yaml_load_multi(text):
    if _yaml is None:
        raise RuntimeError(YAML_HINT)
    return [d for d in _yaml.safe_load_all(text) if d is not None]


def env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def build_cfg(argv=None):
    p = argparse.ArgumentParser(
        prog="hypo-run",
        description="run citi-hypothesis labs end-to-end (preflight -> selection -> execution -> summary)",
        add_help=True,
    )
    p.add_argument("--labs-dir", default=None)
    p.add_argument("--events-file", default=None)
    p.add_argument("--log-file", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--debug", action="store_true",
                   help="verbose logging AND evidence grep + verdict; without it each lab just runs and reports FINISHED")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--no-prompt", action="store_true")
    p.add_argument("--fail-fast", action="store_true")
    p.add_argument("--keep", action="store_true")
    p.add_argument("--no-sudo", action="store_true")
    p.add_argument("--timeout-cmd", type=int, default=None)
    p.add_argument("--timeout-poll", type=int, default=None)
    p.add_argument("--settle", type=int, default=None)
    p.add_argument("--max-log-bytes", type=int, default=None)
    p.add_argument("--max-events", type=int, default=None)
    p.add_argument("--labs", default=None,
                   help="selection by hypothesis number (e.g. 1,3-5,7 or all); "
                        "labs that cannot run in the selected mode report their reason")
    p.add_argument("--backend", default=None,
                   help="execution backend: auto (default), k8s, or operator")
    p.add_argument("--policy-mode", default=None,
                   help="policy form: v1 (default), v2, or auto (by CRS version)")
    p.add_argument("--setup-sensor", action="store_true",
                   help="install the CRS sensor chart per policy mode before running "
                        "(v1 -> HYPO_RUN_CRS_DIR_V1, default /home/ubuntu/arnav/145; "
                        "v2 -> HYPO_RUN_CRS_DIR_V2, default /home/ubuntu/arnav/146)")
    p.add_argument("--version", action="version", version="hypo-run " + __version__)
    args = p.parse_args(argv)

    cfg = SimpleNamespace(**DEFAULTS)
    cfg.labs_dir = args.labs_dir or os.environ.get("HYPO_RUN_LABS_DIR") or os.path.dirname(os.path.abspath(__file__))
    cfg.events_file = args.events_file or os.environ.get("HYPO_RUN_EVENTS_FILE")
    cfg.log_file = args.log_file or os.environ.get("HYPO_RUN_LOG_FILE")
    cfg.dry_run = args.dry_run or env_bool("HYPO_RUN_DRY_RUN")
    cfg.debug = args.debug or args.verbose or env_bool("HYPO_RUN_DEBUG") or env_bool("HYPO_RUN_VERBOSE")
    cfg.yes = args.yes or args.no_prompt or env_bool("HYPO_RUN_YES") or env_bool("HYPO_RUN_NO_PROMPT")
    cfg.fail_fast = args.fail_fast or env_bool("HYPO_RUN_FAIL_FAST")
    cfg.keep = args.keep or env_bool("HYPO_RUN_KEEP")
    cfg.no_sudo = args.no_sudo or env_bool("HYPO_RUN_NO_SUDO")
    cfg.timeout_cmd = args.timeout_cmd or env_int("HYPO_RUN_TIMEOUT_CMD", DEFAULTS["timeout_cmd"])
    cfg.timeout_poll = args.timeout_poll or env_int("HYPO_RUN_TIMEOUT_POLL", DEFAULTS["timeout_poll"])
    cfg.settle = args.settle if args.settle is not None else env_int("HYPO_RUN_SETTLE", DEFAULTS["settle"])
    cfg.max_log_bytes = args.max_log_bytes or env_int("HYPO_RUN_MAX_LOG_BYTES", DEFAULTS["max_log_bytes"])
    cfg.max_events = args.max_events or env_int("HYPO_RUN_MAX_EVENTS", DEFAULTS["max_events"])
    cfg.labs = args.labs or os.environ.get("HYPO_RUN_LABS") or None
    cfg.backend = (args.backend or os.environ.get("HYPO_RUN_BACKEND") or "auto").strip().lower()
    if cfg.backend not in ("auto", "k8s", "operator"):
        p.error("--backend must be auto, k8s, or operator")
    cfg.policy_mode = (args.policy_mode or os.environ.get("HYPO_RUN_POLICY_MODE") or "v1").strip().lower()
    if cfg.policy_mode not in ("auto", "v1", "v2"):
        p.error("--policy-mode must be auto, v1, or v2")
    cfg.setup_sensor = args.setup_sensor or env_bool("HYPO_RUN_SETUP_SENSOR")
    cfg.crs_dir_v1 = os.environ.get("HYPO_RUN_CRS_DIR_V1", "/home/ubuntu/arnav/145")
    cfg.crs_dir_v2 = os.environ.get("HYPO_RUN_CRS_DIR_V2", "/home/ubuntu/arnav/146")

    cfg.repo_root = os.path.dirname(os.path.abspath(__file__))
    cfg.run_dir = os.environ.get("RUN_DIR", RUN_DIR_DEFAULT)
    cfg.ebpf_agent = os.environ.get("EBPF_AGENT", os.path.join(cfg.repo_root, "ebpf-agent"))
    cfg.ebpf_operator = os.environ.get("EBPF_OPERATOR", os.path.join(cfg.repo_root, "ebpf-operator"))
    cfg.bpf_lib = os.environ.get("BPF_LIB", os.path.join(cfg.repo_root, "bpf", "objs"))
    cfg.base_branch = os.environ.get("BASE_BRANCH", BASE_BRANCH_DEFAULT)
    cfg.events_file = cfg.events_file or os.path.join(cfg.run_dir, "events.jsonl")

    if args.timeout_cmd is not None and args.timeout_cmd <= 0:
        p.error("--timeout-cmd must be > 0")
    if args.timeout_poll is not None and args.timeout_poll <= 0:
        p.error("--timeout-poll must be > 0")
    if cfg.max_log_bytes <= 0:
        p.error("--max-log-bytes must be > 0")
    return cfg


CFG = build_cfg()


# --------------------------------------------------------------------------
# phase 1: preflight
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# k8s helpers (kubectl CLI): apply/delete manifests, exec into pods for the
# sensor logs. hypo-run still does the parsing, the approval gate and the
# verdicts itself; kubectl is simply the interface to the cluster.
# --------------------------------------------------------------------------

def detect_backend():
    """auto: k8s when kubectl reaches a cluster; else operator (standalone)."""
    if CFG.backend != "auto":
        return CFG.backend
    rc, _, _ = run(["kubectl", "get", "nodes", "--request-timeout=10s"], quiet=True)
    if rc == 0:
        return "k8s"
    if os.path.isfile(CFG.ebpf_operator) and os.access(CFG.ebpf_operator, os.X_OK):
        return "operator"
    return "operator"


def k8s_apply_manifest(path, lr=None):
    rc, out, err = run(["kubectl", "apply", "-f", path], timeout=CFG.timeout_cmd * 2)
    if rc != 0:
        msg = trim_line(err or out)
        if lr:
            lr.note("kubectl apply %s failed: %s" % (path, msg))
        log("[WARN] kubectl apply %s failed: %s" % (path, msg))
        return False
    log("  applied: %s" % path)
    return True


def k8s_delete_manifest(path, lr=None):
    rc, out, err = run(["kubectl", "delete", "-f", path, "--ignore-not-found=true"],
                       timeout=CFG.timeout_cmd * 2)
    if rc != 0:
        msg = trim_line(err or out)
        if lr:
            lr.note("kubectl delete %s failed (benign if gone): %s" % (path, msg))
        log("[WARN] kubectl delete %s: %s" % (path, msg))
    else:
        log("  deleted: %s" % path)


def k8s_get_runtimepolicy_state(name, mode="v2"):
    # v1 policies live on the policies.qualys.com CRD; v2 on runtimepolicies
    res = "policies" if mode == "v1" else "runtimepolicy"
    rc, out, _ = run(["kubectl", "get", res, name, "-o",
                      "jsonpath={.status.state}", "--request-timeout=10s"], quiet=True)
    return out.strip()


def k8s_get_runtimepolicy_rules(name, mode="v2"):
    res = "policies" if mode == "v1" else "runtimepolicy"
    rc, out, _ = run(["kubectl", "get", res, name, "-o",
                      "jsonpath={.status.rules}", "--request-timeout=10s"], quiet=True)
    return out


def install_sensor(crs_dir, timeout=300):
    """Install (reinstall) the CRS sensor helm chart from crs_dir into the
    qualys namespace, then wait for the sensor pod and the runtimepolicy CRD.
    Mirrors the manual ritual: helm uninstall + helm install qualys-tc."""
    chart = os.path.join(crs_dir, "qualys-tc")
    if not os.path.isdir(chart):
        log("[WARN] sensor chart dir not found: %s" % chart)
        return False
    log("installing CRS sensor from %s" % chart)
    rc, out, err = run(["helm", "uninstall", "qualys-tc", "-n", "qualys"], cwd=crs_dir,
                       timeout=CFG.timeout_cmd * 2)
    if rc != 0:
        log("[WARN] helm uninstall: %s" % trim_line(err or out))
    rc, out, err = run(["helm", "install", "qualys-tc", "./qualys-tc", "-n", "qualys"],
                       cwd=crs_dir, timeout=CFG.timeout_cmd * 2)
    if rc != 0:
        log("[WARN] helm install failed: %s" % trim_line(err or out))
        return False
    log("  helm install ok - waiting for sensor pod + CRDs")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if k8s_sensor_pods():
            rc2, _, _ = run(["kubectl", "get", "crd", "runtimepolicies.qualys.com",
                             "--request-timeout=10s"], quiet=True)
            if rc2 == 0:
                log("  sensor pod up + runtimepolicy CRD present")
                return True
        sleep_check(5)
    log("[WARN] sensor did not become ready within %ds" % timeout)
    return False


def sensor_logs_mention(name):
    """True when the sensor pod logs mention `name` - the v1 approval signal
    (the old CRS does not write CRD status, so fall back to the logs)."""
    for pod in k8s_sensor_pods():
        for f in ("/usr/local/qualys/runtime-sensor/data/logs/ebpfAgentLogFile.log",
                  "/usr/local/qualys/runtime-sensor/data/logs/runtime_sensor.log"):
            rc, out, _ = run(["kubectl", "exec", "-n", "qualys", pod, "--", "cat", f],
                             timeout=CFG.timeout_cmd * 2, quiet=True)
            if rc == 0 and out and name.lower() in out.lower():
                return True
        rc, out, _ = run(["kubectl", "logs", "-n", "qualys", pod, "--tail=2000"], quiet=True)
        if rc == 0 and name.lower() in out.lower():
            return True
    return False


def k8s_sensor_pods():
    rc, out, _ = run(["kubectl", "get", "pods", "-n", "qualys", "--no-headers",
                      "-o", "custom-columns=:metadata.name", "--request-timeout=10s"], quiet=True)
    return [l.strip() for l in out.splitlines() if "qualys-runtime-sensor" in l]


# --------------------------------------------------------------------------
# phase 1: preflight
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# phase 1: preflight
# --------------------------------------------------------------------------

class Preflight:
    def __init__(self):
        self.items = []  # (severity, label, detail); severity in OK/FAIL/WARN/INFO
        self.facts = {}
        self.fatal = False

    def add(self, severity, label, detail=""):
        self.items.append((severity, label, detail))
        log("[%s] %s%s" % (severity, label, (" — " + detail) if detail else ""))
        if severity == "FAIL":
            self.fatal = True

    def print_table(self):
        log("")
        log("preflight summary:")
        for severity, label, detail in self.items:
            log("  [%s] %s" % (severity, label))



def port_listening(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def get_gateway():
    rc, out, _ = run(["ip", "route"], quiet=True)
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"default via (\S+)", line)
            if m:
                return m.group(1)
        return "none"
    # fallback /proc/net/route
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw = parts[2]
                    if gw == "00000000":
                        return "none"
                    return ".".join(str(int(gw[i:i + 2], 16)) for i in (6, 4, 2, 0))
    except OSError:
        pass
    return "unknown"


def get_dns():
    try:
        with open("/etc/resolv.conf") as fh:
            servers = [ln.split()[1] for ln in fh if ln.strip().startswith("nameserver")]
        return servers or ["none"]
    except OSError:
        return ["none"]


def get_listening_ports():
    for cmd in (["ss", "-ltn"], ["netstat", "-ltn"]):
        rc, out, _ = run(cmd, quiet=True)
        if rc == 0:
            ports = sorted({m.group(1) for m in re.finditer(r":(\d+)\s", out)})
            return ports
    return []


def agent_flags():
    """Best-effort: extract ebpf-agent cmdline flags from /proc or log."""
    flags = set()
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(os.path.join("/proc", pid, "cmdline"), "rb") as fh:
                    cl = fh.read().decode("utf-8", errors="replace").split("\x00")
            except OSError:
                continue
            if cl and cl[0].endswith("ebpf-agent"):
                flags.update(a for a in cl if a.startswith("--"))
    except OSError:
        pass
    if not flags:
        # try the setup log
        try:
            with open(os.path.join(CFG.run_dir, "ebpf-agent.log")) as fh:
                for ln in fh:
                    flags.update(m.group(0) for m in re.finditer(r"--[a-z0-9-]+", ln))
        except OSError:
            pass
    return sorted(flags)


def labs_needing_flags(labs):
    """Which labs reference features requiring --enable-process-cred /
    --enable-ancestors (detected from their policies)."""
    need_cred = []
    need_anc = []
    for lab in labs:
        try:
            text = open(lab["policy_path"], encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        low = text.lower()
        if "binary_properties" in low:
            need_cred.append(lab["name"])
        if "ancestors" in low:
            need_anc.append(lab["name"])
    return need_cred, need_anc


def preflight(labs, dry_run=False):
    """Runs all checks; returns the Preflight object."""
    pf = Preflight()

    # 1. root
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pf.add("OK", "running as root")
    elif not hasattr(os, "geteuid"):
        pf.add("WARN", "cannot verify root (non-POSIX platform)")
    elif CFG.no_sudo:
        pf.add("WARN", "not root (--no-sudo): docker/kubectl may fail", "run with sudo for full function")
    else:
        pf.add("FAIL", "not root", "rerun with sudo (or --no-sudo to force)")
        if dry_run:
            pf.fatal = False  # dry-run: only plan, do not abort
            pf.items[-1] = ("WARN", pf.items[-1][1], pf.items[-1][2])

    # 2. prerequisites
    docker_bin = shutil.which("docker")
    if docker_bin:
        rc, _, _ = run(["docker", "ps"], quiet=True)
        if rc == 0:
            pf.add("OK", "docker daemon responding")
        else:
            pf.add("WARN", "docker installed but daemon not responding", "docker ps failed")
    else:
        pf.add("FAIL" if not dry_run else "WARN", "docker not installed")
    if shutil.which("go"):
        pf.add("OK", "go toolchain present")
    else:
        pf.add("WARN", "go toolchain missing", "only needed to rebuild binaries")
    if shutil.which("python3"):
        pf.add("OK", "python3 present")
    else:
        pf.add("FAIL", "python3 missing", "hypo-run itself needs python3")

    # 3. binaries: distinguish not-installed from not-running.
    #    The k8s backend does not need the standalone binaries at all.
    for label, path in (("ebpf-agent", CFG.ebpf_agent), ("ebpf-operator", CFG.ebpf_operator)):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            pf.add("OK", "%s present (%s)" % (label, path))
        elif CFG.backend == "k8s":
            pf.add("INFO", "%s not installed (not needed for k8s backend)" % label)
        else:
            pf.add("FAIL" if not dry_run else "WARN", "%s not installed" % label,
                   "expected at %s - run citi-hypothesis/setup.sh" % path)

    # 4. agent running + gRPC :54321
    if port_listening(54321):
        pf.add("OK", "ebpf-agent gRPC listening on 127.0.0.1:54321")
    else:
        pf.add("FAIL" if not dry_run else "WARN", "ebpf-agent not running",
               "port 54321 not listening — start with citi-hypothesis/setup.sh")

    # 5. capture file exists, readable, growing.
    #    The k8s backend reads evidence from the sensor pod logs instead.
    cap = CFG.events_file
    if CFG.backend == "k8s":
        if os.path.isfile(cap):
            pf.add("INFO", "local capture present (%d bytes) - k8s backend also reads sensor pod logs" % os.path.getsize(cap))
        else:
            pf.add("INFO", "no local capture file - evidence comes from sensor pod logs (k8s backend)")
    elif os.path.isfile(cap) and os.access(cap, os.R_OK):
        try:
            s1 = os.path.getsize(cap)
            sleep_check(2)
            s2 = os.path.getsize(cap)
            if s2 > s1:
                pf.add("OK", "capture growing (%d -> %d bytes)" % (s1, s2))
            else:
                pf.add("WARN", "capture not growing", "stale or stopped capture at %s" % cap)
                offer_restart_capture(pf)
        except OSError as e:
            pf.add("WARN", "capture unreadable", str(e))
    else:
        pf.add("WARN", "capture file missing", cap)
        offer_restart_capture(pf)

    # 6. write access
    for d in (CFG.run_dir, os.path.dirname(CFG.events_file) or CFG.run_dir):
        if os.path.isdir(d) and os.access(d, os.W_OK):
            pf.add("OK", "write access %s" % d)
        else:
            pf.add("FAIL" if not dry_run else "WARN", "no write access to %s" % d)

    # 7. environment facts
    facts = {
        "kernel": platform.release() or "unknown",
        "hostname": socket.gethostname() or "unknown",
        "ip": "unknown",
        "gateway": get_gateway(),
        "dns": get_dns(),
        "ports": get_listening_ports(),
        "docker": docker_summary(),
        "agent_flags": agent_flags(),
    }
    rc, out, _ = run(["hostname", "-I"], quiet=True)
    if rc == 0 and out.strip():
        facts["ip"] = out.strip().split()[0]
    log("[INFO] kernel=%s host=%s ip=%s gateway=%s dns=%s" % (
        facts["kernel"], facts["hostname"], facts["ip"], facts["gateway"], ",".join(facts["dns"])))
    if facts["ports"]:
        log("[INFO] listening ports: %s" % ",".join(facts["ports"]))
    else:
        log("[INFO] listening ports: (none detected — ss/netstat unavailable)")
    log("[INFO] docker: %s" % (facts["docker"] or "no daemon info"))
    if facts["agent_flags"]:
        log("[INFO] agent flags: %s" % " ".join(facts["agent_flags"]))

    # agent flags vs labs
    need_cred, need_anc = labs_needing_flags(labs)
    flags = facts["agent_flags"]
    if need_cred and "--enable-process-cred" not in flags:
        pf.add("WARN", "agent lacks --enable-process-cred",
               "affects: %s (binary_properties fields)" % ", ".join(need_cred))
    if need_anc and "--enable-ancestors" not in flags:
        pf.add("WARN", "agent lacks --enable-ancestors",
               "affects: %s (ancestor chain fields)" % ", ".join(need_anc))

    # 8. git branch
    rc, out, _ = run(["git", "-C", CFG.repo_root, "branch", "--show-current"], quiet=True)
    branch = out.strip() if rc == 0 else "unknown"
    if branch == CFG.base_branch:
        pf.add("OK", "on supported base branch %s" % branch)
    else:
        pf.add("WARN", "not on supported base branch",
               "on '%s', labs verified on '%s'" % (branch, CFG.base_branch))

    # 9. disk space
    for d in (CFG.run_dir, os.path.dirname(CFG.events_file) or CFG.run_dir):
        try:
            usage = shutil.disk_usage(d)
            free_mb = usage.free / (1024 * 1024)
            if free_mb < 500:
                pf.add("WARN", "low disk space on %s" % d, "%.0f MB free" % free_mb)
            else:
                pf.add("OK", "disk space on %s: %.0f MB free" % (d, free_mb))
        except OSError:
            pf.add("WARN", "cannot stat disk on %s" % d)

    # 10. k8s backend specifics
    if CFG.backend == "k8s":
        rc, out, err = run(["kubectl", "get", "nodes", "--request-timeout=10s"], quiet=True)
        if rc == 0:
            pf.add("OK", "kubectl cluster reachable")
        else:
            pf.add("FAIL" if not dry_run else "WARN", "kubectl cluster not reachable",
                   trim_line(err or out))
        rc, out, _ = run(["kubectl", "get", "crd", "runtimepolicies.qualys.com",
                          "--request-timeout=10s"], quiet=True)
        if rc == 0:
            pf.add("OK", "runtimepolicy CRD present")
        else:
            pf.add("WARN", "runtimepolicy CRD missing", "kubectl get crd failed")
        pods = k8s_sensor_pods()
        if pods:
            pf.add("OK", "sensor pod(s) in qualys ns: %s" % ", ".join(pods))
        else:
            pf.add("WARN", "no qualys-runtime-sensor pod found in namespace qualys")

    pf.facts = facts
    return pf


def docker_summary():
    rc, out, _ = run(["docker", "info", "--format", "{{.ServerVersion}}|{{.Driver}}|{{.OperatingSystem}}"],
                     quiet=True)
    if rc != 0:
        return ""
    parts = out.strip().split("|")
    return "server %s, storage %s, os %s" % (parts[0], parts[1], parts[2]) if len(parts) == 3 else out.strip()


def offer_restart_capture(pf):
    if CFG.dry_run:
        return
    if CFG.yes or not has_tty():
        log("[WARN] capture stale/missing — run 'sudo citi-hypothesis/setup.sh' to restart")
        return
    try:
        ans = prompt("[WARN] restart the event capture now (runs setup.sh)? [y/N] ", default="n")
    except Abort:
        raise
    if str(ans).strip().lower() in ("y", "yes"):
        rc, out, err = run(["bash", os.path.join(CFG.repo_root, "setup.sh")],
                           timeout=max(CFG.timeout_cmd, 120))
        if rc == 0:
            pf.add("OK", "capture restarted via setup.sh")
        else:
            pf.add("WARN", "capture restart failed", trim_line(err or out))


# --------------------------------------------------------------------------
# phase 2: labs + selection
# --------------------------------------------------------------------------

NATURAL_RE = re.compile(r"QCS-H(\d+)")


def lab_sort_key(name):
    m = NATURAL_RE.search(name)
    return (int(m.group(1)) if m else 1 << 30, name)


def policy_mode_for(crs_version_str):
    """Policy mode: v1 by default; 'auto' picks v1 for CRS <= 1.45, else v2."""
    if CFG.policy_mode != "auto":
        return CFG.policy_mode
    m = re.search(r"(\d{1,2})\.(\d{1,2})", crs_version_str or "")
    if m and (int(m.group(1)), int(m.group(2))) <= (1, 45):
        return "v1"
    return "v2"


def scan_labs(labs_dir):
    """Returns (runnable_labs, not_runnable) — natural numeric order."""
    labs = []
    try:
        entries = os.listdir(labs_dir)
    except OSError as e:
        raise RuntimeError("cannot list labs dir %s: %s" % (labs_dir, e))
    for entry in sorted(entries, key=lab_sort_key):
        d = os.path.join(labs_dir, entry)
        if not os.path.isdir(d) or not NATURAL_RE.match(entry):
            continue
        hnum_m = re.search(r"H(\d+)", entry)
        lab = {
            "name": entry,
            "hnum": int(hnum_m.group(1)) if hnum_m else None,
            "dir": d,
            "policy_v2_path": os.path.join(d, "policy-v2.yaml"),
            "policy_v1_path": os.path.join(d, "policy-v1.yaml"),
            "policy_path": "",
            "pod_path": os.path.join(d, "pod.yaml"),
            "tracing_path": os.path.join(d, "tracingpolicy.yaml"),
            "result_path": os.path.join(d, "RESULT.md"),
            "enforce_pod_path": os.path.join(d, "pod-enforce.yaml"),
            "enforce_policy_v2_path": os.path.join(d, "policy-enforce.yaml"),
            "enforce_policy_v1_path": os.path.join(d, "policy-v1-enforce.yaml"),
            "enforce_policy_path": "",
            "enforce_policy": None,
            "enforce_pod": None,
            "runnable": True,
            "reason": "",
            "verdict": "",
            "crs_version": "",
            "mode": "v2",
            "policy": None,
            "pod": None,
        }
        lab["verdict"] = result_verdict(lab["result_path"])
        lab["crs_version"] = crs_version(lab["result_path"], lab["pod_path"])
        # pick the policy file by CRS version: v1 for CRS <= 1.45, else v2
        lab["mode"] = policy_mode_for(lab["crs_version"])
        chosen = lab["policy_v2_path"] if lab["mode"] == "v2" else lab["policy_v1_path"]
        if not os.path.isfile(chosen):
            alt = lab["policy_v1_path"] if lab["mode"] == "v2" else lab["policy_v2_path"]
            if CFG.policy_mode == "auto" and os.path.isfile(alt):
                # auto mode picks whichever form exists
                lab["mode"] = "v1" if lab["mode"] == "v2" else "v2"
                chosen = alt
            elif os.path.isfile(alt):
                # explicit mode requested but only the other form ships:
                # report "not supported in <mode>" instead of silently
                # switching (H01/H20 have no v1 form)
                lab["unsupported_mode"] = True
        lab["policy_path"] = chosen
        problems = []
        if lab.get("unsupported_mode"):
            other = "v2" if lab["mode"] == "v1" else "v1"
            problems.append("not supported in %s (only a %s policy form exists — use --policy-mode %s)"
                            % (lab["mode"], other, other))
        elif not os.path.isfile(lab["policy_path"]):
            problems.append("missing %s" % os.path.basename(chosen))
        if not os.path.isfile(lab["pod_path"]):
            problems.append("missing pod.yaml")
        if problems:
            lab["runnable"] = False
            lab["reason"] = "; ".join(problems)
        else:
            # parse (best-effort); malformed yaml -> not runnable with message
            try:
                lab["policy"] = parse_policy_yaml(lab["policy_path"])
                lab["pod"] = parse_pod_yaml(lab["pod_path"])
                # two-phase labs (QCS-H02): enforcement policy + workload manifest
                ef_pol = lab["enforce_policy_v2_path"] if lab["mode"] == "v2" else lab["enforce_policy_v1_path"]
                if os.path.isfile(ef_pol) and os.path.isfile(lab["enforce_pod_path"]):
                    lab["enforce_policy"] = parse_policy_yaml(ef_pol)
                    lab["enforce_pod"] = parse_pod_yaml(lab["enforce_pod_path"])
                    lab["enforce_policy_path"] = ef_pol
            except Exception as e:
                lab["runnable"] = False
                lab["reason"] = "malformed YAML: %s" % e
        labs.append(lab)
    runnable = [l for l in labs if l["runnable"]]
    not_runnable = [l for l in labs if not l["runnable"]]
    return runnable, not_runnable


def parse_policy_yaml(path):
    """Parse a RuntimePolicy file (may contain several RuntimePolicy docs)."""
    text = open(path, encoding="utf-8", errors="replace").read()
    docs = yaml_load_multi(text)
    names = []
    rules = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        # accept qualys.com RuntimePolicy docs (kind RuntimePolicy) or any doc
        # carrying rules; the fallback scanner has no kind field for policies
        # beyond what it captured, so accept docs that have rules or a name
        if doc.get("kind") not in (None, "RuntimePolicy"):
            continue
        md = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        n = md.get("name") or doc.get("name") or ""
        if n and n not in names:
            names.append(n)
        raw_rules = (doc.get("spec") or {}).get("rules")
        if raw_rules is None:
            raw_rules = doc.get("rules")
        for r in (raw_rules or []):
            if not isinstance(r, dict):
                continue
            rules.append({
                "name": r.get("name", ""),
                "id": r.get("id", r.get("name", "")),
                "type": r.get("type", ""),
                "action": r.get("action", ""),
                "operator": r.get("operator", ""),
                "values": (r.get("values") or [])[:6],
                "raw": json.dumps(r, sort_keys=True)[:400],
            })
    if not names:
        # fallback scanner may have merged everything into one doc
        m = re.search(r"^name:\s*(\S+)", text, re.M)
        if m:
            names.append(m.group(1))
    base_policy = ""
    monitor_paths = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        spec = doc.get("spec") or {}
        bp = spec.get("base-policy")
        if bp:
            base_policy = str(bp)
        mp = spec.get("monitor-paths")
        if isinstance(mp, list):
            monitor_paths.extend(str(v) for v in mp if isinstance(v, str) and v.startswith("/"))
    return {"names": names, "name": names[0] if names else "",
            "rules": rules, "base_policy": base_policy,
            "monitor_paths": monitor_paths, "text": text}


def parse_pod_yaml(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    docs = yaml_load_multi(text)
    # collect workload docs (Pod/Job/Deployment/...); prefer the one with the
    # richest command (the test case rather than a negative/restricted variant)
    kinds = ("Pod", "Job", "Deployment", "CronJob", "StatefulSet", "DaemonSet", "ReplicaSet")
    pods = [d for d in docs if isinstance(d, dict) and d.get("kind") in kinds]
    if not pods:
        pods = [docs[0]] if docs else [{}]
    pod = max(pods, key=lambda d: sum(len(str(c)) for c in _pod_command(d)))
    spec = pod.get("spec") or {}
    template = (spec.get("template") or {}).get("spec") or {}
    containers = (spec.get("containers") or template.get("containers") or [])
    container = containers[0] if containers else {}
    md = pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
    # fall back to top-level fields for hand-written minimal manifests
    name = md.get("name") or pod.get("name") or ""
    image = container.get("image") or pod.get("image") or ""
    command = _pod_command(pod)
    privileged = bool((container.get("securityContext") or {}).get("privileged"))
    if not privileged:
        privileged = bool((spec.get("securityContext") or {}).get("privileged")
                          or (template.get("securityContext") or {}).get("privileged"))
    return {
        "kind": pod.get("kind", ""),
        "name": name,
        "image": image,
        "command": command,
        "privileged": privileged,
        "text": text,
    }


def _pod_command(pod):
    """Command from a workload doc in structured, template, or flat shape."""
    spec = pod.get("spec") or {}
    template = (spec.get("template") or {}).get("spec") or {}
    containers = (spec.get("containers") or template.get("containers") or [])
    container = containers[0] if containers else {}
    cmd = (container.get("command") or container.get("args")
           or pod.get("command") or [])
    if not isinstance(cmd, list):
        cmd = [cmd]
    return [str(c) for c in cmd]


def pod_activity_tokens(pod, monitor_paths=None):
    """Activity tokens for matching base-sensor process_exec evidence in v1
    mode (v1 has no process-exec policy, so the only real proof that the
    workload's binaries ran is the sensor's policy-free exec stream).

    Tokens come from the pod command and the v1 policy: runtime script paths
    (/tmp/... - unique per lab), the binaries the policy watches
    (monitor-paths), and lab markers that surface in exec args (CITI-HNN-...,
    *marker*). Generic bare commands (sh, echo, sleep, ...) are intentionally
    excluded - they would match unrelated events across the whole cluster's
    exec stream. Returns up to 12 unique tokens.
    """
    cmd = " ".join(str(c) for c in (pod or {}).get("command") or [])
    tokens = []
    seen = set()

    def add(tok):
        tok = tok.strip()
        if tok and tok not in seen:
            seen.add(tok)
            tokens.append(tok)

    # runtime scripts the workload creates and executes (/tmp/...) - unique
    for m in re.finditer(r"(?<![A-Za-z0-9_@.+-])(/tmp/[A-Za-z0-9_@.+~/-]+)", cmd):
        add(m.group(1))
    # the binaries the v1 policy watches (monitor-paths)
    for p in (monitor_paths or []):
        add(str(p))
    # lab markers that surface in exec args (CITI-HNN-..., *marker*)
    for m in re.finditer(r"\b(CITI-H\d\d[-\w]*|[\w-]+marker[\w-]*|CHAIN-DONE)\b", cmd):
        add(m.group(1))
    return tokens[:12]


def result_verdict(result_path):
    try:
        text = open(result_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
    m = re.search(r"^## Verdict\s*\n(.*)", text, re.M)
    if not m:
        return ""
    line = m.group(1).strip()
    line = re.sub(r"[*_`]", "", line)
    return trim_line(line, 60)


def crs_version(result_path, pod_path=None):
    texts = []
    for p in (result_path, pod_path):
        if p and os.path.isfile(p):
            try:
                texts.append(open(p, encoding="utf-8", errors="replace").read())
            except OSError:
                pass
    text = "\n".join(texts)
    if not text:
        return ""
    # explicit mentions win
    m = re.search(
        r"(?:CRS version support|CRS version|sensor version|requires)\D{0,20}?(\d{1,2}\.\d{1,2}(?:\+)?)",
        text, re.I)
    if m:
        return m.group(1)
    # fallback: standalone version tokens, skipping IP-like numbers (major > 32)
    for m in re.finditer(r"(?<![\d.])(\d{1,2}\.\d{1,2})\+?(?![\d.])", text[:2000]):
        if int(m.group(1).split(".")[0]) <= 32:
            return m.group(1)
    return ""


class SelectionError(Exception):
    pass


def parse_selection(text, max_index):
    """Strict selection parser. Returns sorted unique list of 1-based ints."""
    if text == "":
        return list(range(1, max_index + 1))
    if text.lower() in ("all", "a"):
        return list(range(1, max_index + 1))
    tokens = text.split(",")
    idxs = []
    for tok_raw in tokens:
        tok = tok_raw.strip()  # tolerate accidental outer spaces, reject inner
        if re.fullmatch(r"[0-9]+", tok):
            n = int(tok)
            if n == 0:
                raise SelectionError("index 0 is not a lab")
            if n > max_index:
                raise SelectionError("%d out of range (1-%d)" % (n, max_index))
            idxs.append(n)
        elif re.fullmatch(r"[0-9]+-[0-9]+", tok):
            lo_s, hi_s = tok.split("-")
            lo, hi = int(lo_s), int(hi_s)
            if lo == 0 or hi == 0:
                raise SelectionError("ranges must start at 1 (got '%s')" % tok)
            if lo > hi:
                raise SelectionError("reversed range '%s' (use %d-%d)" % (tok, hi, lo))
            if hi > max_index:
                raise SelectionError("%d out of range (1-%d)" % (hi, max_index))
            idxs.extend(range(lo, hi + 1))
        else:
            raise SelectionError("cannot parse '%s' (use e.g. 3, 3-7, 1,3-5,7 or all)" % tok)
    if not idxs:
        raise SelectionError("empty selection")
    seen = set()
    dups = []
    for i in idxs:
        if i in seen:
            dups.append(i)
        seen.add(i)
    if dups:
        raise SelectionError("duplicate index(es) %s (e.g. 1,3-5,7)" % sorted(set(dups)))
    return sorted(seen)


class UsageError(Exception):
    pass


def prompt_selection(max_index):
    if not has_tty() and CFG.labs is None:
        log("[WARN] no TTY and no --labs — defaulting to all runnable labs")
        return list(range(1, max_index + 1))
    if CFG.labs is not None:
        try:
            return parse_selection(CFG.labs.strip(), max_index)
        except SelectionError as e:
            raise UsageError("bad --labs value: %s" % e)
    while True:
        try:
            text = input("select labs (e.g. 1,3-5,7 / all / Enter=all) > ")
        except EOFError:
            raise Abort()
        except KeyboardInterrupt:
            raise Abort()
        try:
            return parse_selection(text.strip(), max_index)
        except SelectionError as e:
            log("[WARN] %s — try e.g. 1,3-5,7 or all" % e)


# --------------------------------------------------------------------------
# phase 3: per-lab execution
# --------------------------------------------------------------------------

class LabResult:
    def __init__(self, lab):
        self.lab = lab
        self.verdict = "PENDING"
        self.evidence_count = 0
        self.notes = []
        self.duration_s = 0.0
        self.state = {
            "policy_installed": False,
            "pod_applied": False,
            "evidence_seen": False,
            "enforcement_observed": False,
        }
        self.not_applied = []
        self.left_installed = []

    def note(self, msg):
        self.notes.append(msg)
        log("    note: %s" % msg)


def briefing(lab, ctx):
    log("")
    log("=" * 70)
    title = lab["name"]
    hypothesis = "no RESULT.md — using directory name"
    try:
        text = open(lab["result_path"], encoding="utf-8", errors="replace").read()
        m = re.search(r"^#\s+(.+)$", text, re.M)
        if m:
            title = m.group(1).strip()
        m = re.search(r"^## What we wanted to prove\s*\n+(.+?)(?:\n##|\Z)", text, re.S | re.M)
        if m:
            hypothesis = " ".join(m.group(1).split())[:300]
    except OSError:
        pass
    log("HYPOTHESIS: %s" % title)
    log("  %s" % hypothesis)
    log("  recorded verdict: %s | CRS: %s" % (lab["verdict"] or "n/a", lab["crs_version"] or "n/a"))
    log("  policy mode: %s (%s)" % (lab.get("mode", "v2"), os.path.basename(lab["policy_path"])))
    if lab.get("mode") == "v1":
        log("  note: v1 policy - legacy form, global 1-minute rate limit (bursts drop events)")
    log("")
    log("mapping:")
    pod = lab["pod"] or {}
    if pod.get("image"):
        log("  workload (pod.yaml): image %s, name %s" % (pod["image"], pod.get("name") or "?"))
        cmd = " ".join(str(c) for c in pod.get("command") or [])
        if cmd:
            log("    command: %s" % trim_line(cmd))
    policy = lab["policy"] or {}
    if policy.get("rules"):
        log("  policy rules:")
        for r in policy["rules"]:
            log("    - %s (type=%s action=%s id=%s)" % (r["name"] or "?", r["type"] or "?",
                                                         r["action"] or "?", r["id"] or "?"))
    log("  expected evidence: events matching policy '%s' (and its -v2-<rule> variants)"
        % (policy.get("name") or lab["name"]))
    if lab.get("enforce_policy_path"):
        log("  note: two-phase lab - enforcement phase follows (policy %s + %s)"
            % (os.path.basename(lab["enforce_policy_path"]), os.path.basename(lab["enforce_pod_path"])))
    if lab["tracing_path"] and os.path.isfile(lab["tracing_path"]):
        log("  note: raw tracingpolicy.yaml present — will be applied as fallback too")


def not_applied_warnings(policy, install_output):
    """Detect rules the v2 translator cannot apply (never fire)."""
    warns = []
    text = (policy or {}).get("text", "")
    low = text.lower()
    for r in (policy or {}).get("rules") or []:
        rlow = (r.get("raw") or "").lower()
        reasons = []
        if "matchqlps" in rlow:
            reasons.append("matchQLPs not supported by v2")
        if "containerselector" in rlow:
            reasons.append("containerSelector not supported by v2")
        if r.get("type") == "network" and r.get("action") in ("block",):
            if "matchports" in rlow or "matchbinaries" in rlow:
                reasons.append("matchPorts/matchBinaries ignored on network block rules")
        if reasons:
            warns.append((r.get("id") or r.get("name") or "?", "; ".join(reasons)))
    if low.find("not-applied") >= 0 or low.find("not applied") >= 0:
        warns.append(("policy", "translator marks rules Not-applied"))
    outlow = (install_output or "").lower()
    if "not-applied" in outlow or "not applied" in outlow:
        warns.append(("install output", "translator marked rules Not-applied"))
    return warns


def policy_installed_name(policy):
    base = (policy or {}).get("name") or ""
    return base


def list_installed_policies():
    """Names of installed policies (operator list or k8s API list)."""
    if CFG.backend == "k8s":
        rc, out, _ = run(["kubectl", "get", "runtimepolicy", "-o", "name",
                          "--request-timeout=10s"], quiet=True)
        return "\n".join(l.split("/", 1)[-1] for l in out.splitlines() if l.strip())
    rc, out, _ = run([CFG.ebpf_operator, "tracingpolicy", "list"], quiet=True)
    if rc != 0:
        return ""
    return out


def install_policy(lab, ctx, lr):
    """Backend dispatcher: k8s (API) or operator (standalone binary)."""
    if CFG.backend == "k8s":
        return k8s_install_policy(lab, lr)
    return operator_install_policy(lab, lr)


def k8s_install_policy(lab, lr):
    """Apply policy.yaml via kubectl and poll the CRD status until 'Applied'
    (the approval gate)."""
    policy = lab["policy"] or {}
    names = policy.get("names") or ([policy.get("name")] if policy.get("name") else [lab["name"]])
    return k8s_install_policy_file(lab["policy_path"], policy, names, lab.get("mode", "v2"), lr)


def k8s_install_policy_file(path, policy, names, mode, lr):
    """Apply a RuntimePolicy manifest via kubectl and poll the approval gate
    (status.state == Applied for every name; v1 falls back to the sensor logs
    because the CRD status stays empty on old CRS charts)."""
    log("")
    log("installing policy via kubectl: %s (%s)" % (", ".join(names), path))

    # deterministic: delete-then-re-add if already installed
    st = k8s_get_runtimepolicy_state(names[0], mode)
    if st != "":
        log("  policy '%s' already installed - deleting then re-adding (deterministic)" % names[0])
        k8s_delete_manifest(path, lr)

    if not k8s_apply_manifest(path, lr):
        lr.note("policy not applied")
        return False

    # gate: poll status.state == Applied for every policy name
    deadline = time.time() + CFG.timeout_poll
    all_applied = False
    last = ""
    while time.time() < deadline and not interrupted():
        statuses = []
        for n in names:
            statuses.append((n, k8s_get_runtimepolicy_state(n, mode)))
        last = "; ".join("%s=%s" % (n, s) for n, s in statuses)
        if statuses and all(s == "Applied" for _, s in statuses):
            all_applied = True
            break
        if mode == "v1" and statuses and all(s == "" for _, s in statuses):
            if any(sensor_logs_mention(n) for n, _ in statuses):
                log("  v1 approval confirmed in sensor logs (CRD status empty on old CRS)")
                all_applied = True
                break
        sleep_check(2)
    if interrupted():
        lr.left_installed.extend(names)
        lr.note("interrupted during policy install - leaving policy installed")
        return False
    if all_applied:
        log("  policy approved: %s" % last)
        # per-rule Not-applied warnings
        for n in names:
            rules_out = k8s_get_runtimepolicy_rules(n, mode)
            for m in re.finditer(r'"state"\s*:\s*"Not-applied"', rules_out):
                rid = "?"
                mm = re.search(r'"id"\s*:\s*"([^"]+)"[^}]*?"state"\s*:\s*"Not-applied"', rules_out)
                if mm:
                    rid = mm.group(1)
                lr.not_applied.append((rid, "translator marked rule Not-applied"))
                log("[WARN] rule '%s' will never fire: Not-applied" % rid)
        warns = not_applied_warnings(policy, "")
        for rid, why in warns:
            if not any(a == rid for a, _ in lr.not_applied):
                lr.not_applied.append((rid, why))
                log("[WARN] rule '%s' will never fire: %s" % (rid, why))
        return True
    lr.note("policy never reached Applied state (last: %s)" % last)
    log("[WARN] policy never reached Applied state (last: %s)" % last)
    return False


def operator_install_policy(lab, lr):
    """Returns True if the policy is installed (polled)."""
    policy = lab["policy"] or {}
    base = policy.get("name") or lab["name"]
    log("")
    log("installing policy '%s' (%s)" % (base, lab["policy_path"]))

    # already installed? deterministic: delete then re-add
    existing = list_installed_policies()
    if base in existing:
        log("  policy already installed — deleting then re-adding (deterministic)")
        rc, out, err = run([CFG.ebpf_operator, "tracingpolicy", "delete", base, "--all-rules"])
        if rc != 0:
            log("  [WARN] delete of pre-existing policy failed (continuing): %s" % trim_line(err or out))

    # add policy.yaml (v2 -> auto-translated)
    proc = stream_start([CFG.ebpf_operator, "tracingpolicy", "add", lab["policy_path"]],
                        cwd=CFG.repo_root)
    if proc is None:
        lr.note("could not start ebpf-operator (missing binary?)")
        return False

    # poll until 'policy installed' or budget exhausted
    deadline = time.time() + CFG.timeout_poll
    rc, out, err = None, "", ""
    installed = False
    while time.time() < deadline:
        if interrupted():
            lr.state["policy_installed"] = False
            lr.left_installed.append(base)
            lr.note("interrupted during policy install — leaving policy installed")
            kill_group(proc)
            return False
        if proc.poll() is not None:
            rc, out, err = stream_finish(proc)
            break
        # check the list for the translated policy (names are <base>-v2-<rule>)
        listing = list_installed_policies()
        if base in listing or any(base in line for line in listing.splitlines()):
            installed = True
            break
        sleep_check(2)
    if proc.poll() is None and not installed:
        kill_group(proc)
        rc, out, err = stream_finish(proc)
    if installed:
        # the add CLI may still be exiting; don't leave an orphan
        if proc.poll() is None:
            kill_group(proc)
        lr.state["policy_installed"] = True
        log("  policy installed (confirmed via tracingpolicy list)")
    elif rc == 0:
        # exited 0 but not yet visible: give it one final poll
        deadline2 = time.time() + 5
        while time.time() < deadline2:
            listing = list_installed_policies()
            if base in listing:
                installed = True
                break
            if any(line.strip().startswith(base) for line in listing.splitlines()):
                installed = True
                break
            sleep_check(1)
        if installed:
            lr.state["policy_installed"] = True
            log("  policy installed (exit 0 + present in list)")
        else:
            lr.state["policy_installed"] = True  # exit 0 is authoritative enough
            log("  policy add exited 0 (assumed installed)")
    else:
        lr.note("policy install failed (rc=%s): %s" % (rc, trim_line(err or out)))
        log("[WARN] %s" % trim_line(err or out))
        return False

    # Not-applied warnings
    warns = not_applied_warnings(policy, (out or "") + (err or ""))
    for rid, why in warns:
        lr.not_applied.append((rid, why))
        log("[WARN] rule '%s' will never fire: %s" % (rid, why))

    # raw fallback
    if lab["tracing_path"] and os.path.isfile(lab["tracing_path"]):
        log("  applying raw tracingpolicy fallback: %s" % lab["tracing_path"])
        rc2, out2, err2 = run([CFG.ebpf_operator, "tracingpolicy", "add", lab["tracing_path"]],
                              timeout=CFG.timeout_poll)
        if rc2 == 0:
            log("  raw tracingpolicy applied")
        else:
            lr.note("raw tracingpolicy add failed: %s" % trim_line(err2 or out2))
            log("[WARN] raw tracingpolicy add failed: %s" % trim_line(err2 or out2))
    return True


def cluster_reachable():
    if not shutil.which("kubectl"):
        return False
    rc, out, err = run(["kubectl", "get", "nodes", "--request-timeout=10s"], quiet=True)
    if rc == 0:
        return True
    return False


def kubectl_objects_exist(pod_path):
    rc, out, _ = run(["kubectl", "get", "-f", pod_path, "-o", "name"], quiet=True)
    return rc == 0 and out.strip() != ""


def apply_pod(lab, ctx, lr):
    log("")
    log("applying workload: %s" % lab["pod_path"])
    pod = lab["pod"] or {}
    if pod.get("image"):
        log("  container image: %s (name: %s)" % (pod["image"], pod.get("name") or "?"))
    cmd = " ".join(str(c) for c in pod.get("command") or [])
    if cmd:
        log("  activity: %s" % trim_line(cmd))
    else:
        log("  note: no explicit command in pod.yaml - image entrypoint is the activity")

    if CFG.backend == "k8s":
        k8s_apply_pod(lab, lr)
        return
    # operator backend: kubectl if a cluster answers, else docker fallback
    if cluster_reachable():
        log("  using kubectl (cluster reachable)")
        if kubectl_objects_exist(lab["pod_path"]):
            log("  objects already exist - deleting first (deterministic)")
            rc, out, err = run(["kubectl", "delete", "-f", lab["pod_path"], "--ignore-not-found=true"],
                               timeout=CFG.timeout_cmd * 2)
            if rc != 0:
                lr.note("delete of existing objects failed: %s" % trim_line(err or out))
        rc, out, err = run(["kubectl", "apply", "-f", lab["pod_path"]], timeout=CFG.timeout_cmd * 2)
        if rc == 0:
            lr.state["pod_applied"] = True
            log("  applied (kubectl)")
        else:
            lr.note("kubectl apply failed: %s" % trim_line(err or out))
            log("[WARN] kubectl apply failed: %s" % trim_line(err or out))
        pod_statuses = wait_pod_status(lab)
        if pod_statuses:
            test_pod = (lab["pod"] or {}).get("name") or ""
            for name, status in pod_statuses:
                if status in CONTROL_FAIL_STATES and name != test_pod:
                    continue  # control pod failing is expected (negative control)
                if status in ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "ImagePullError"):
                    lr.note("pod %s in %s - weak evidence (activity may not have run)" % (name, status))
                    log("[WARN] pod %s in %s - activity may not have run" % (name, status))
    else:
        log("  kubectl unavailable or cluster unreachable - falling back to docker")
        lr.note("docker fallback used (no cluster) - evidence is weaker")
        docker_run_pod(lab, lr)


READY_POD_STATES = ("Running", "Succeeded", "Completed")
CONTROL_FAIL_STATES = ("CreateContainerConfigError", "ImagePullBackOff",
                       "ErrImagePull", "CrashLoopBackOff", "ImagePullError")


def pod_readiness(statuses, test_pod="", expect_fail=False):
    """Workload readiness from (name, status) pairs: (ready, control_failures).

    A negative/control pod (any pod other than the test pod) failing to
    start (CreateContainerConfigError / image errors) is expected and does
    not weaken the evidence — the test pod being ready is what matters.
    expect_fail (enforcement phase): a Failed test pod is the expected
    outcome — the policy killed it (SIGKILL evidence is checked later)."""
    ok_states = READY_POD_STATES + (("Failed",) if expect_fail else ())
    if not statuses:
        return False, 0
    test = dict(statuses).get(test_pod, "")
    if test in ok_states:
        failures = [(n, s) for n, s in statuses if n != test_pod and s not in READY_POD_STATES]
        if failures and all(s in CONTROL_FAIL_STATES for _, s in failures):
            return True, len(failures)
    return all(s in ok_states for _, s in statuses), 0


def k8s_apply_pod(lab, lr, expect_fail=False):
    """Apply pod.yaml via kubectl; deterministic delete-then-apply; wait for
    the workload to actually run before evidence collection."""
    log("  using kubectl apply (deterministic delete-then-apply)")
    k8s_delete_manifest(lab["pod_path"], lr)
    if k8s_apply_manifest(lab["pod_path"], lr):
        lr.state["pod_applied"] = True
    wait_budget = min(180, max(CFG.timeout_poll, 60))
    statuses = k8s_wait_pod_status(lab, wait_s=wait_budget)
    if statuses:
        test_pod = (lab["pod"] or {}).get("name") or ""
        ready, ctrl_fail = pod_readiness(statuses, test_pod, expect_fail)
        if ready:
            if expect_fail and dict(statuses).get(test_pod) == "Failed":
                log("  workload done: %s — pod Failed as expected (enforcement killed it)"
                    % "; ".join("%s=%s" % (n, s) for n, s in statuses))
            else:
                log("  workload ready: %s" % "; ".join("%s=%s" % (n, s) for n, s in statuses))
            if ctrl_fail:
                log("    control pod(s) failed to start as expected (negative control)")
        else:
            lr.note("workload not ready within %ds: %s - evidence likely weak"
                    % (wait_budget, "; ".join("%s=%s" % (n, s) for n, s in statuses)))
            log("[WARN] workload not ready within %ds: %s - evidence likely weak"
                % (wait_budget, "; ".join("%s=%s" % (n, s) for n, s in statuses)))
    for name, status in statuses:
        if status in CONTROL_FAIL_STATES and name != (lab["pod"] or {}).get("name"):
            continue  # control pod failing is expected (negative control)
        if status in ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "ImagePullError"):
            lr.note("pod %s in %s - weak evidence (activity may not have run)" % (name, status))
            log("[WARN] pod %s in %s - activity may not have run" % (name, status))


def k8s_wait_pod_status(lab, wait_s=60):
    """Finite wait for workload pod statuses via kubectl."""
    pods = []
    try:
        for d in yaml_load_multi(open(lab["pod_path"], encoding="utf-8", errors="replace").read()):
            if not isinstance(d, dict):
                continue
            md = d.get("metadata") or {}
            kind = d.get("kind")
            ns = md.get("namespace") or "default"
            name = md.get("name") or ""
            if kind in ("Pod", "Job", "Deployment", "StatefulSet", "DaemonSet",
                        "ReplicaSet", "CronJob") and name:
                pods.append((kind, name, ns))
    except OSError:
        pass
    statuses = []
    deadline = time.time() + wait_s
    while time.time() < deadline and not interrupted():
        statuses = []
        for kind, name, ns in pods:
            if kind == "Pod":
                rc, out, _ = run(["kubectl", "get", "pod", name, "-n", ns, "-o",
                                  "jsonpath={.status.phase}|{.status.containerStatuses[0].state.waiting.reason}",
                                  "--request-timeout=10s"], quiet=True)
                phase, _, reason = out.strip().partition("|")
                statuses.append((name, reason or phase))
            else:
                rc, out, _ = run(["kubectl", "get", "pods", "-n", ns, "--no-headers",
                                  "-o", "custom-columns=:metadata.name", "--request-timeout=10s"], quiet=True)
                names = [l.strip() for l in out.splitlines() if l.strip().startswith(name + "-")]
                for pn in names or [name + "-?"]:
                    rc2, out2, _ = run(["kubectl", "get", "pod", pn, "-n", ns, "-o",
                                        "jsonpath={.status.phase}|{.status.containerStatuses[0].state.waiting.reason}",
                                        "--request-timeout=10s"], quiet=True)
                    phase, _, reason = out2.strip().partition("|")
                    statuses.append((pn, reason or phase))
        if statuses and all(s in ("Running", "Succeeded", "Completed") for _, s in statuses):
            break
        if any(s in ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff") for _, s in statuses):
            break
        sleep_check(2)
    return statuses


def wait_pod_status(lab, wait_s=60):
    """Finite wait for pod statuses; returns [(name, status)] (kubectl path)."""
    names = []
    try:
        for d in yaml_load_multi(open(lab["pod_path"], encoding="utf-8", errors="replace").read()):
            if isinstance(d, dict) and d.get("kind") == "Pod":
                md = d.get("metadata") or {}
                if md.get("name"):
                    names.append(md["name"])
    except OSError:
        pass
    statuses = []
    deadline = time.time() + wait_s
    while time.time() < deadline and not interrupted():
        rc, out, _ = run(["kubectl", "get", "pods", "-A", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,REASON:.status.containerStatuses[0].state.waiting.reason"],
                         quiet=True)
        if rc == 0:
            statuses = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] in names:
                    reason = parts[2] if len(parts) > 2 and parts[2] not in ("Running", "Succeeded", "Pending") else ""
                    statuses.append((parts[0], reason or parts[1]))
            if all(status in ("Running", "Succeeded") for _, status in statuses) and statuses:
                break
            if any(status in ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff") for _, status in statuses):
                break
        sleep_check(2)
    return statuses


def docker_run_pod(lab, lr):
    pod = lab["pod"] or {}
    name = ("hypo-" + (pod.get("name") or lab["name"])).replace("_", "-")
    image = pod.get("image")
    if not image:
        lr.note("no image in pod.yaml — cannot docker-run")
        log("[WARN] no image in pod.yaml — docker fallback cannot run")
        return
    run(["docker", "rm", "-f", name], quiet=True)  # benign failure tolerated
    cmd = [pod.get("command")[0]] if pod.get("command") else None
    cmd_args = []
    if pod.get("command"):
        c = pod["command"]
        if len(c) >= 3 and c[0] in ("sh", "bash") and c[1] == "-c":
            cmd_args = ["sh", "-c", c[2]]
        else:
            cmd_args = list(c)
    docker_cmd = ["docker", "run", "-d", "--name", name]
    if pod.get("privileged"):
        docker_cmd.append("--privileged")
    docker_cmd.append(image)
    docker_cmd.extend(cmd_args or [])
    rc, out, err = run(docker_cmd, timeout=CFG.timeout_cmd * 2)
    if rc == 0:
        lr.state["pod_applied"] = True
        log("  docker run ok: %s" % trim_line(out))
    else:
        lr.note("docker run failed: %s" % trim_line(err or out))
        log("[WARN] docker run failed: %s" % trim_line(err or out))
    # finite wait + status
    deadline = time.time() + 45
    while time.time() < deadline and not interrupted():
        rc2, out2, _ = run(["docker", "inspect", "-f", "{{.State.Status}}", name], quiet=True)
        if rc2 == 0 and out2.strip():
            status = out2.strip()
            if status in ("running", "exited"):
                if status == "exited":
                    lr.note("docker container exited early — weak evidence")
                    log("[WARN] container %s exited early" % name)
                else:
                    log("  container %s running" % name)
                return
        sleep_check(2)
    lr.note("docker container never reached running state")
    log("[WARN] container %s never reached running state" % name)


def grep_evidence(lab, ctx, lr, since=None):
    """Gather evidence for this lab's policy.

    k8s backend: sensor pod logs via the k8s API (the lab's events carry the
    policy/rule ids); operator backend: the capture file. In v1 mode the
    policy has no process-exec rule, so we also match activity tokens
    (pod.yaml binaries/scripts + v1 monitor paths) against the base-sensor
    process_exec stream. `since` (epoch seconds) windows timestamped lines
    to this lab's run. Returns (evidence, {"policy": n, "activity": n,
    "tokens": m}) - counts recomputed on the deduped list.
    """
    policy = lab["policy"] or {}
    base = policy.get("name") or lab["name"]
    rule_ids = [r.get("id") or r.get("name") or "" for r in (policy.get("rules") or []) if r.get("id") or r.get("name")]
    variants = set([base])
    for rid in rule_ids:
        if rid:
            variants.add("%s-v2-%s" % (base, rid))
    if policy.get("base_policy"):
        variants.add(policy["base_policy"])
    variants_l = [v for v in variants if v]

    activity_tokens = []
    if lab.get("mode") == "v1":
        activity_tokens = pod_activity_tokens(lab["pod"] or {}, policy.get("monitor_paths") or [])
        if activity_tokens:
            log("  v1 activity tokens (base-sensor process_exec evidence): %s"
                % ", ".join(activity_tokens))

    evidence = []
    if CFG.backend == "k8s":
        evidence = k8s_sensor_evidence(variants_l, rule_ids, activity_tokens, since=since)
    if not evidence and os.path.isfile(CFG.events_file):
        cap = CFG.events_file
        try:
            size = os.path.getsize(cap)
            start = max(0, size - CFG.max_log_bytes)
            with open(cap, "rb") as fh:
                if start:
                    fh.seek(start)
                    fh.readline()  # drop partial first line
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError as e:
            lr.note("cannot read capture: %s" % e)
            return evidence, {"policy": 0, "activity": 0, "tokens": len(activity_tokens)}
        for line in tail.splitlines():
            line = line.strip()
            if not line:
                continue
            if interrupted():
                break
            hit, key, _ = event_matches(line, variants_l, rule_ids, activity_tokens, since=since)
            if hit:
                evidence.append(line)
    evidence = dedupe_evidence(evidence)
    pol = act = 0
    for line in evidence:
        _, _, kind = event_matches(line, variants_l, rule_ids, activity_tokens, since=since)
        if kind == "policy":
            pol += 1
        elif kind == "activity":
            act += 1
    return evidence, {"policy": pol, "activity": act, "tokens": len(activity_tokens)}


def dedupe_evidence(lines):
    seen = set()
    out = []
    for line in lines:
        key = None
        try:
            ev = json.loads(line)
            key = ((ev.get("metadata") or {}).get("uid") or ev.get("correlation_uid")
                   or ((ev.get("metadata") or {}).get("correlation_uid")) or "")
        except (ValueError, TypeError, AttributeError):
            pass
        key = key or line
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out


def k8s_sensor_evidence(variants_l, rule_ids, activity_tokens=None, since=None):
    """Evidence from the qualys-runtime-sensor pod.

    The event payloads live in log FILES inside the pod (and in its stdout).
    Read them with kubectl exec cat (with kubectl logs as fallback - the
    sensor may SIGKILL the cat, exit 137). Matches policy variants / rule ids
    and, in v1 mode, activity tokens (base-sensor process_exec visibility).
    `since` (epoch seconds) windows timestamped lines to this lab's run."""
    pods = k8s_sensor_pods()
    if not pods:
        log("[WARN] no qualys-runtime-sensor pod found in namespace qualys")
        return []
    files = [
        "/usr/local/qualys/runtime-sensor/data/logs/runtime_sensor.log",
        "/usr/local/qualys/runtime-sensor/data/logs/ebpfAgentLogFile.log",
    ]
    evidence = []
    seen = set()
    for pod in pods:
        for f in files:
            if interrupted():
                return evidence
            logtxt = ""
            for attempt in (1, 2):
                rc, out, err = run(["kubectl", "exec", "-n", "qualys", pod, "--", "cat", f],
                                   timeout=CFG.timeout_cmd * 2, quiet=True)
                if rc == 0 and out:
                    logtxt = out
                    break
                log("[WARN] kubectl exec cat %s (attempt %d) failed: %s"
                    % (f, attempt, trim_line(err or out)))
                sleep_check(1)
            if not logtxt:
                rc, out, _ = run(["kubectl", "logs", "-n", "qualys", pod, "--tail=5000"], quiet=True)
                logtxt = out
            if not logtxt:
                continue
            log("  sensor log %s: %d lines" % (f, len(logtxt.splitlines())))
            for line in logtxt.splitlines():
                line = line.strip()
                if not line:
                    continue
                if since is not None:
                    ts = line_timestamp(line)
                    if ts is not None and ts < since:
                        continue
                if not (any(v.lower() in line.lower() for v in variants_l)
                        or any(rid and rid.lower() in line.lower() for rid in rule_ids)
                        or (activity_tokens and any(t.lower() in line.lower() for t in activity_tokens))):
                    continue
                key = line[:200]
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(line)
    return evidence


def line_timestamp(line):
    """Best-effort UTC epoch seconds for an evidence line, else None.

    Handles the sensor log's leading ISO-8601 timestamps
    (2026-11-05T22:23:23.453Z) and JSON events' epoch-millis 'time' field.
    """
    m = re.match(r"^\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|(?:[+-]\d{2}:?\d{2})?))", line)
    if m:
        try:
            ts = m.group(1)
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return datetime.fromisoformat(ts).timestamp()
        except ValueError:
            return None
    try:
        ev = json.loads(line)
        t = ev.get("time")
        if isinstance(t, (int, float)) and t > 1e12:  # milliseconds
            return t / 1000.0
        if isinstance(t, (int, float)):
            return float(t)
    except (ValueError, TypeError, AttributeError):
        pass
    return None


def event_matches(line, variants, rule_ids, activity_tokens=None, since=None, _depth=0):
    """Structured JSON attempt, then raw substring fallback.

    Returns (matched, dedupe_key, kind); kind is 'policy' (policy name /
    rule id) or 'activity' (base-sensor process_exec visibility token, v1
    mode). Policy hits win over activity hits when both apply. When
    `since` (epoch seconds) is given, timestamped lines older than it are
    excluded (evidence window - a lab must not count a previous run's
    events); lines with no parseable timestamp are kept.
    """
    if _depth > 30:
        return False, None, None
    if since is not None:
        ts = line_timestamp(line)
        if ts is not None and ts < since:
            return False, None, None
    key = None
    try:
        ev = json.loads(line)
        # dedupe key
        key = (
            (ev.get("metadata") or {}).get("uid")
            or ev.get("correlation_uid")
            or (ev.get("metadata") or {}).get("correlation_uid")
            or ""
        )
        # structured: policy_name anywhere
        def find_policy(obj, depth=0):
            if depth > 30:
                return False
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "policy_name" and isinstance(v, str):
                        if any(v == var or var in v for var in variants):
                            return True
                    if find_policy(v, depth + 1):
                        return True
            elif isinstance(obj, list):
                for v in obj:
                    if find_policy(v, depth + 1):
                        return True
            return False

        # structured: any string field carrying an activity token
        def find_activity(obj, depth=0):
            if depth > 30:
                return False
            if isinstance(obj, dict):
                for v in obj.values():
                    if isinstance(v, str) and any(t in v for t in activity_tokens):
                        return True
                    if find_activity(v, depth + 1):
                        return True
            elif isinstance(obj, list):
                for v in obj:
                    if find_activity(v, depth + 1):
                        return True
            return False

        policy_hit = find_policy(ev)
        # correlation_uid == rule id
        cu = (ev.get("metadata") or {}).get("correlation_uid") or ev.get("correlation_uid")
        if cu and cu in rule_ids:
            policy_hit = True
        if policy_hit:
            return True, key or line, "policy"
        if activity_tokens and find_activity(ev):
            return True, key or line, "activity"
    except (ValueError, TypeError, AttributeError):
        pass
    # raw substring fallback
    low = line.lower()
    for var in variants:
        if var.lower() in low:
            return True, key or line, "policy"
    if activity_tokens:
        for tok in activity_tokens:
            if tok.lower() in low:
                return True, key or line, "activity"
    return False, None, None


def print_evidence(evidence):
    shown = evidence[: max(1, CFG.max_events)]
    for ev in shown:
        log("    " + trim_line(ev))
    rest = len(evidence) - len(shown)
    if rest > 0:
        log("    ... and %d more" % rest)


def cleanup_lab(lab, ctx, lr):
    if CFG.keep:
        lr.note("--keep: policy and pod left in place")
        log("  --keep: leaving policy and pod in place")
        for n in (lab["policy"] or {}).get("names") or [(lab["policy"] or {}).get("name") or lab["name"]]:
            lr.left_installed.append(n)
        return
    log("  cleanup: deleting policy + pod")
    if CFG.backend == "k8s":
        k8s_cleanup_lab(lab, lr)
        return
    base = (lab["policy"] or {}).get("name") or lab["name"]
    rc, out, err = run([CFG.ebpf_operator, "tracingpolicy", "delete", base, "--all-rules"])
    if rc != 0:
        lr.note("policy delete failed (benign if already gone): %s" % trim_line(err or out))
        log("[WARN] policy delete: %s" % trim_line(err or out))
    if lab["tracing_path"] and os.path.isfile(lab["tracing_path"]):
        rc2, out2, err2 = run([CFG.ebpf_operator, "tracingpolicy", "delete",
                               os.path.splitext(os.path.basename(lab["tracing_path"]))[0], "--all-rules"])
        if rc2 != 0:
            log("[WARN] raw tracingpolicy delete: %s" % trim_line(err2 or out2))
    if cluster_reachable():
        rc3, out3, err3 = run(["kubectl", "delete", "-f", lab["pod_path"], "--ignore-not-found=true"],
                              timeout=CFG.timeout_cmd * 2)
        if rc3 != 0:
            lr.note("pod delete failed: %s" % trim_line(err3 or out3))
            log("[WARN] pod delete: %s" % trim_line(err3 or out3))
    else:
        name = ("hypo-" + ((lab["pod"] or {}).get("name") or lab["name"])).replace("_", "-")
        run(["docker", "rm", "-f", name], quiet=True)


def k8s_cleanup_lab(lab, lr):
    log("  cleanup: deleting policy + pod")
    k8s_delete_manifest(lab["policy_path"], lr)
    if lab["tracing_path"] and os.path.isfile(lab["tracing_path"]):
        k8s_delete_manifest(lab["tracing_path"], lr)
    k8s_delete_manifest(lab["pod_path"], lr)


def run_enforce_phase(lab, ctx, lr):
    """Phase B for two-phase labs (QCS-H02): enforcement policy + workload.

    The audit phase already ran and produced evidence. Here we: remove the
    audit pod + audit policy, show and apply the enforcement policy (waiting
    for the approval gate), echo what the enforcement pod will do, run it,
    gather evidence, print the summary, clean up, and mark the lab done."""
    log("")
    log("=" * 70)
    log("going for the enforcement phase")
    ef_t0 = time.time()
    log("  removing audit policy + pod")
    k8s_delete_manifest(lab["pod_path"], lr)
    k8s_delete_manifest(lab["policy_path"], lr)

    ef_pol = lab["enforce_policy"] or {}
    names = ef_pol.get("names") or ([ef_pol.get("name")] if ef_pol.get("name") else [lab["name"] + "-enforce"])
    mode = lab.get("mode", "v2")
    log("")
    log("applying the enforcement policy: %s" % ", ".join(names))
    try:
        txt = open(lab["enforce_policy_path"], encoding="utf-8", errors="replace").read()
        log("  --- enforcement policy ---")
        for line in txt.splitlines():
            log("  " + line)
        log("  --- end policy ---")
    except OSError:
        log("  (cannot read %s)" % lab["enforce_policy_path"])
    if interrupted():
        return False
    if not k8s_install_policy_file(lab["enforce_policy_path"], ef_pol, names, mode, lr):
        lr.note("enforcement policy not applied")
        return False
    log("  policy applied: %s" % ", ".join(names))

    ef_pod = lab["enforce_pod"] or {}
    log("")
    log("what the enforcement pod will do:")
    cmd = " ".join(str(c) for c in ef_pod.get("command") or [])
    if cmd:
        log("  %s" % trim_line(cmd))
    else:
        log("  (image entrypoint - no explicit command)")
    ef_lab = {
        "name": lab["name"] + "-enforce",
        "mode": mode,
        "policy": ef_pol,
        "pod": ef_pod,
        "policy_path": lab["enforce_policy_path"],
        "pod_path": lab["enforce_pod_path"],
    }
    if CFG.backend != "k8s":
        lr.note("enforcement phase requires the k8s backend")
        log("[WARN] enforcement phase requires the k8s backend")
        return False
    log("  applying workload: %s" % lab["enforce_pod_path"])
    k8s_apply_pod(ef_lab, lr, expect_fail=True)
    if interrupted():
        return False
    log("")
    log("waiting %ds for events to settle..." % CFG.settle)
    sleep_check(CFG.settle)
    log("grepping enforcement evidence (policy '%s')..." % (ef_pol.get("name") or lab["name"]))
    evidence, ev_counts = grep_evidence(ef_lab, ctx, lr, since=ef_t0)
    lr.state["enforce_evidence"] = len(evidence)
    lr.state["enforce_policy_evidence"] = ev_counts.get("policy", 0)
    lr.state["enforce_activity_evidence"] = ev_counts.get("activity", 0)
    if evidence:
        log("  enforcement evidence: %d matching event(s) (policy-name/rule-id: %d, activity/process_exec: %d)"
            % (len(evidence), ev_counts.get("policy", 0), ev_counts.get("activity", 0)))
        print_evidence(evidence)
        joined = " ".join(evidence[:50]).lower()
        if ("sigkill" in joined) or ("kill" in joined and "137" in joined) or ("status.*failure" in joined):
            lr.state["enforcement_observed"] = True
            log("  enforcement observed (SIGKILL / exit-137 style evidence)")
    else:
        lr.note("enforcement phase: no matching evidence (may be disproven)")
        log("[WARN] enforcement phase: no matching evidence (may be disproven)")
    log("")
    log("cleanup: deleting enforcement pod + policy")
    k8s_delete_manifest(lab["enforce_pod_path"], lr)
    k8s_delete_manifest(lab["enforce_policy_path"], lr)
    log("QCS-H02 hypothesis done (audit + enforcement phases complete)")
    lr.state["two_phase"] = True
    return True


def run_lab(lab, idx, ctx):
    lr = LabResult(lab)
    t0 = time.time()
    try:
        briefing(lab, ctx)
        if interrupted():
            lr.verdict = "ABORTED"
            lr.note("interrupted before policy install")
            return lr
        ok = install_policy(lab, ctx, lr)
        if not ok:
            lr.verdict = "SKIPPED"
            lr.note("policy not installed")
            if CFG.fail_fast:
                lr.note("--fail-fast: stopping after this lab")
            return lr
        if interrupted():
            lr.verdict = "ABORTED"
            return lr
        apply_pod(lab, ctx, lr)
        if interrupted():
            lr.verdict = "ABORTED"
            lr.note("interrupted after pod apply")
            return lr
        log("")
        log("waiting %ds for events to settle..." % CFG.settle)
        sleep_check(CFG.settle)
        if not CFG.debug:
            lr.verdict = "FINISHED"
            log("lab finished - review the events in the Qualys UI "
                "(no verdict: evidence grep runs only with --debug)")
            if lab.get("enforce_policy_path") and CFG.backend == "k8s":
                run_enforce_phase(lab, ctx, lr)
            else:
                cleanup_lab(lab, ctx, lr)
            return lr
        log("grepping evidence (policy '%s')..." % ((lab["policy"] or {}).get("name") or lab["name"]))
        evidence, ev_counts = grep_evidence(lab, ctx, lr, since=t0)
        lr.evidence_count = len(evidence)
        lr.state["evidence_seen"] = len(evidence) > 0
        lr.state["policy_evidence"] = ev_counts.get("policy", 0)
        lr.state["activity_evidence"] = ev_counts.get("activity", 0)
        if evidence:
            lr.verdict = "PROVEN"
            log("  evidence: %d matching event(s) (policy-name/rule-id: %d, activity/process_exec: %d)"
                % (len(evidence), ev_counts.get("policy", 0), ev_counts.get("activity", 0)))
            print_evidence(evidence)
            joined = " ".join(evidence[:50]).lower()
            if ("sigkill" in joined) or ("kill" in joined and "137" in joined) or ("status.*failure" in joined):
                lr.state["enforcement_observed"] = True
                log("  enforcement observed (SIGKILL / exit-137 style evidence)")
            if lab.get("mode") == "v1":
                if ev_counts.get("activity", 0) > 0 and ev_counts.get("policy", 0) == 0:
                    lr.note("v1: activity/process_exec evidence only (%d hit(s)) - base-sensor "
                            "process visibility; no v1 policy payload (v1 has no process-exec "
                            "base-policy)" % ev_counts.get("activity", 0))
                elif ev_counts.get("tokens", 0) > 0 and ev_counts.get("activity", 0) == 0:
                    lr.note("v1: policy-name matches only (%d) - may be operator lifecycle "
                            "lines; no activity/process_exec hit(s) for %d expected token(s)"
                            % (ev_counts.get("policy", 0), ev_counts.get("tokens", 0)))
        else:
            lr.verdict = "NOT-PROVEN"
            log("[NOT-PROVEN] hypothesis not verified by events (may be disproven)")
        if interrupted():
            lr.verdict = "ABORTED"
            lr.note("interrupted after evidence collection")
            return lr
        if lab.get("enforce_policy_path") and CFG.backend == "k8s":
            run_enforce_phase(lab, ctx, lr)
        else:
            cleanup_lab(lab, ctx, lr)
    except Abort:
        lr.verdict = "ABORTED"
        lr.note("aborted at prompt")
    except Exception as e:  # never let one lab kill the run
        lr.verdict = "SKIPPED"
        lr.note("unexpected error: %s" % e)
        log("[WARN] lab failed with unexpected error: %s" % e)
    finally:
        lr.duration_s = round(time.time() - t0, 1)
    return lr


# --------------------------------------------------------------------------
# phase 4: report
# --------------------------------------------------------------------------

def format_duration(seconds):
    return "%.1fs" % seconds


def build_report(results, started_at, finished_at, exit_reason, pf, selected, not_runnable,
                 left_installed):
    labs_out = []
    for lr in results:
        labs_out.append({
            "index": lr.lab.get("_index"),
            "name": lr.lab["name"],
            "mode": lr.lab.get("mode", "v2"),
            "verdict": lr.verdict,
            "evidence_count": lr.evidence_count,
            "duration_s": lr.duration_s,
            "notes": lr.notes,
            "state": lr.state,
            "not_applied": [{"rule": a, "reason": b} for a, b in lr.not_applied],
        })
    return {
        "tool": "hypo-run",
        "version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": round(finished_at - started_at, 1),
        "exit_reason": exit_reason,
        "env": pf.facts,
        "preflight": [{"severity": s, "label": l, "detail": d} for s, l, d in pf.items],
        "selection": selected,
        "labs": labs_out,
        "not_runnable": [{"name": l["name"], "reason": l["reason"]} for l in not_runnable],
        "left_installed": left_installed,
    }


def write_report_atomic(report, path):
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def write_md_atomic(report, path):
    lines = []
    lines.append("# hypo-run report")
    lines.append("")
    lines.append("- started: %s" % report["started_at"])
    lines.append("- finished: %s (%s)" % (report["finished_at"], format_duration(report["duration_s"])))
    lines.append("- exit reason: %s" % report["exit_reason"])
    lines.append("- env: kernel %s, host %s, ip %s, gateway %s, dns %s"
                 % (report["env"].get("kernel"), report["env"].get("hostname"),
                    report["env"].get("ip"), report["env"].get("gateway"),
                    ",".join(report["env"].get("dns") or [])))
    lines.append("")
    lines.append("## Labs")
    lines.append("")
    lines.append("| # | lab | verdict | evidence | duration | notes |")
    lines.append("|---|-----|---------|----------|----------|-------|")
    for l in report["labs"]:
        notes = "; ".join((l.get("notes") or [])[:3])
        lines.append("| %s | %s | %s | %d | %s | %s |" % (
            l.get("index", "?"), l.get("name", "?"), l.get("verdict", "?"),
            l.get("evidence_count", 0),
            format_duration(l.get("duration_s", 0.0)), notes.replace("|", "/")))
    if report["left_installed"]:
        lines.append("")
        lines.append("## Left installed (interrupted)")
        for p in report["left_installed"]:
            lines.append("- %s" % p)
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def print_summary(results, not_runnable, exit_reason):
    log("")
    log("-" * 70)
    log("CONSOLIDATED SUMMARY (exit: %s)" % exit_reason)
    log("%-3s %-30s %-11s %-9s %-9s %s" % ("#", "lab", "verdict", "evidence", "duration", "notes"))
    log("%-3s %-30s %-11s %-9s %-9s %s" % ("-" * 3, "-" * 30, "-" * 11, "-" * 9, "-" * 9, "-" * 20))
    for lr in results:
        notes = "; ".join(lr.notes[:2])
        log("%-3s %-30s %-11s %-9s %-9s %s" % (
            lr.lab.get("_index", "?"), lr.lab["name"], lr.verdict, lr.evidence_count,
            format_duration(lr.duration_s), trim_line(notes, 40)))
    if not_runnable:
        log("")
        log("not runnable labs:")
        for l in not_runnable:
            log("  - %s: %s" % (l["name"], l["reason"]))
    log("-" * 70)


def detect_stale_policies():
    """Report policies left by a crashed previous run (idempotent re-runs)."""
    listing = list_installed_policies()
    if not listing:
        return []
    names = [line.strip() for line in listing.splitlines() if line.strip()]
    # only warn about lab policies (citi-h*), not unrelated cluster policies
    lab_names = [n for n in names if n.startswith("citi-h")]
    if lab_names:
        log("[WARN] stale lab policies detected (possibly left by a previous run):")
        for n in lab_names:
            log("  - %s" % n)
    return lab_names


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def args_backend_label():
    return os.environ.get("HYPO_RUN_BACKEND") or "auto"


def detect_backend_label():
    return CFG.backend if hasattr(CFG, "backend") else "?"


def main():
    global CFG, LOG_FH
    # ensure UTF-8 output streams (non-UTF8 consoles otherwise mangle output)
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    CFG = build_cfg()
    started_at = time.time()

    # log file tee
    if CFG.log_file:
        try:
            LOG_FH = open(CFG.log_file, "a", encoding="utf-8")
        except OSError as e:
            logerr("[FAIL] cannot open --log-file %s: %s" % (CFG.log_file, e))
            return 2

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    log("hypo-run %s — %s" % (__version__, time.strftime("%Y-%m-%d %H:%M:%S")))
    log("repo root: %s | labs dir: %s | run dir: %s | events: %s"
        % (CFG.repo_root, CFG.labs_dir, CFG.run_dir, CFG.events_file))
    log("dry-run: %s | keep: %s | fail-fast: %s | settle: %ds | timeout-cmd: %ds | timeout-poll: %ds"
        % (CFG.dry_run, CFG.keep, CFG.fail_fast, CFG.settle, CFG.timeout_cmd, CFG.timeout_poll))
    try:
        CFG.backend = detect_backend()
        log("backend: %s (requested: %s)" % (CFG.backend, args_backend_label()))
    except Exception as e:
        log("backend detection failed: %s" % e)

    if _yaml is None:
        logerr("[FAIL] %s" % YAML_HINT)
        return 1

    # single instance
    lock = acquire_lock(CFG.run_dir)
    if lock is None:
        logerr("[FAIL] another hypo-run instance is in progress (lock: %s/hypo-run.lock)"
               % CFG.run_dir)
        return 1

    results = []
    selected = []
    not_runnable = []
    runnable = []
    pf = Preflight()
    exit_reason = "completed"
    left_installed = []

    try:
        # phase 1
        log("")
        log("== PHASE 1: PREFLIGHT ==")
        runnable, not_runnable = scan_labs(CFG.labs_dir)
        if CFG.dry_run:
            log("[INFO] dry-run: preflight findings below will not block the run")
        pf = preflight(runnable, dry_run=CFG.dry_run)
        if not CFG.dry_run and pf.fatal:
            pf.print_table()
            logerr("[FAIL] preflight failed — aborting (exit 1). Use --dry-run to plan without checks.")
            exit_reason = "preflight-failed"
            return  # the finally block writes the report and maps the exit code

        # stale policies from a previous crashed run (idempotent re-runs)
        if not CFG.dry_run:
            stale = detect_stale_policies()
            if stale:
                log("[WARN] consider: ./ebpf-operator tracingpolicy delete <name> --all-rules")

        # phase 2 — selection is by hypothesis number (QCS-H01 -> 1), so a
        # lab that cannot run in the requested mode still shows up when
        # selected (with its reason) instead of silently remapping
        log("")
        log("== PHASE 2: SELECTION ==")
        all_labs = runnable + not_runnable
        by_hnum = {l["hnum"]: l for l in all_labs if l.get("hnum") is not None}
        for i, lab in enumerate(all_labs):
            lab["_index"] = lab["hnum"] if lab.get("hnum") is not None else (i + 1)
            if lab.get("hnum") is None:
                by_hnum.setdefault(lab["_index"], lab)
        log("runnable labs (%d):" % len(runnable))
        for lab in runnable:
            log("  %2d. %-32s verdict=%s crs=%s mode=%s" % (lab["_index"], lab["name"],
                                                              lab["verdict"] or "n/a",
                                                              lab["crs_version"] or "n/a",
                                                              lab.get("mode", "v2")))
        if not_runnable:
            log("not runnable (selectable — will report the reason):")
            for l in not_runnable:
                log("     - %2d. %s: %s" % (l["_index"], l["name"], l["reason"]))
        if not runnable:
            logerr("[FAIL] no runnable labs — nothing to do")
            exit_reason = "no-runnable-labs"
            return

        max_hnum = max(by_hnum) if by_hnum else len(all_labs)
        try:
            if CFG.dry_run and not CFG.labs:
                log("dry-run: no --labs given — planning all %d labs" % len(by_hnum))
                selected = sorted(by_hnum)
            else:
                selected = prompt_selection(max_hnum)
        except UsageError as e:
            logerr("[FAIL] %s" % e)
            exit_reason = "usage-error"
            return
        except Abort:
            log("aborted at selection prompt")
            exit_reason = "interrupted"
            raise

        unknown = [n for n in selected if n not in by_hnum]
        if unknown:
            logerr("[FAIL] no lab numbered: %s" % ", ".join(str(n) for n in unknown))
            exit_reason = "usage-error"
            return
        selected_labs = [by_hnum[n] for n in selected]
        log("selected %d lab(s): %s" % (len(selected),
                                         ", ".join("%d=%s" % (n, by_hnum[n]["name"]) for n in selected)))
        if CFG.dry_run:
            log("")
            log("== DRY-RUN PLAN ==")
            for lab in selected_labs:
                if not lab["runnable"]:
                    log("  %2d. %s — %s" % (lab["_index"], lab["name"], lab["reason"]))
                    continue
                pod = lab["pod"] or {}
                rules = ", ".join(r.get("id") or r.get("name") or "?" for r in (lab["policy"] or {}).get("rules") or [])
                log("  %2d. %s" % (lab["_index"], lab["name"]))
                log("      policy: %s" % ((lab["policy"] or {}).get("name") or lab["name"]))
                if rules:
                    log("      rules : %s" % rules)
                log("      pod   : image=%s name=%s" % (pod.get("image") or "?", pod.get("name") or "?"))
                log("      verdict recorded in RESULT.md: %s" % (lab["verdict"] or "n/a"))
            log("")
            log("dry-run complete — no side effects performed")
            exit_reason = "dry-run"
            return 0

        # phase 3 — selection order preserved; not-runnable picks report
        # their reason; per-lab verdict printed as each finishes
        log("")
        log("== PHASE 3: EXECUTION ==")
        cur_mode = None
        for _gi, lab in enumerate(selected_labs, 1):
            if interrupted():
                exit_reason = "interrupted"
                break
            log("")
            log(">>> [%d/%d] lab %s: %s" % (_gi, len(selected_labs), lab["_index"], lab["name"]))
            if not lab["runnable"]:
                # selected but cannot run in the requested mode/setup
                log("  %s" % lab["reason"])
                lr = LabResult(lab)
                lr.verdict = "NOT SUPPORTED" if "not supported" in lab["reason"] else "SKIPPED"
                lr.note(lab["reason"])
                lr.duration_s = 0.0
                results.append(lr)
                continue
            mode = lab.get("mode", "v2")
            if CFG.setup_sensor and mode != cur_mode:
                # run v1 labs on the old CRS (145) and v2 labs on the current CRS (146)
                crs_dir = CFG.crs_dir_v1 if mode == "v1" else CFG.crs_dir_v2
                if not install_sensor(crs_dir):
                    log("[WARN] sensor setup for mode %s failed - continuing on current sensor" % mode)
            cur_mode = mode
            if not CFG.yes and has_tty():
                try:
                    ans = prompt("  run this lab now? [Y/n] ", default="y")
                except Abort:
                    log("aborted at lab confirmation")
                    exit_reason = "interrupted"
                    break
                if str(ans).strip().lower() in ("n", "no"):
                    log("  skipped by user")
                    lr = LabResult(lab)
                    lr.verdict = "SKIPPED"
                    lr.note("skipped by user at confirmation")
                    lr.duration_s = 0.0
                    results.append(lr)
                    continue
            lr = run_lab(lab, lab["_index"], None)
            results.append(lr)
            left_installed.extend(lr.left_installed)
            log("<<< lab %s done: %s — %d evidence, %s" % (
                lab["_index"], lr.verdict, lr.evidence_count, format_duration(lr.duration_s)))
            if interrupted():
                exit_reason = "interrupted"
                break
            if CFG.fail_fast and lr.verdict in ("SKIPPED", "NOT-PROVEN", "NOT SUPPORTED"):
                log("[WARN] --fail-fast: stopping after lab %s (%s)" % (lab["name"], lr.verdict))
                exit_reason = "fail-fast"
                break

        # phase 4
        if not interrupted() and exit_reason not in ("interrupted", "fail-fast", "usage-error"):
            exit_reason = "completed"
    except Abort:
        if exit_reason != "interrupted":
            exit_reason = "interrupted"
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as e:
        logerr("[FAIL] unexpected error: %s" % e)
        if exit_reason == "completed":
            exit_reason = "env-error"
    finally:
        finished_at = time.time()
        if interrupted() or exit_reason == "interrupted":
            exit_reason = "interrupted"
        if not INTERRUPTED["reported"]:
            INTERRUPTED["reported"] = True
            report = build_report(results, started_at, finished_at, exit_reason, pf,
                                  selected, not_runnable, left_installed)
            ts = time.strftime("%Y%m%d-%H%M%S")
            base = os.path.join(CFG.run_dir, "hypo-run-%s" % ts)
            try:
                write_report_atomic(report, base + ".json")
                write_md_atomic(report, base + ".md")
                log("")
                log("report written: %s.json / %s.md" % (base, base))
            except OSError as e:
                logerr("[WARN] could not write report: %s" % e)
            print_summary(results, not_runnable, exit_reason)
        release_lock()
        if LOG_FH is not None:
            try:
                LOG_FH.close()
            except Exception:
                pass
        if exit_reason == "interrupted":
            return 130
        if exit_reason in ("preflight-failed", "no-runnable-labs", "env-error"):
            return 1
        if exit_reason == "usage-error":
            return 2
        return 0


if __name__ == "__main__":
    sys.exit(main())