"""Containment self-test. Each check tries to do something the sandbox should
block. contained=True means the attempt was blocked. Results go to /out/report.json.
"""
import json
import os
import socket
import stat
import subprocess
import time

results = []


def check(name, attempt):
    """attempt() returns (succeeded: bool, detail: str). Success means it escaped."""
    try:
        succeeded, detail = attempt()
    except Exception as exc:  # an exception means the action was blocked
        succeeded, detail = False, f"blocked: {type(exc).__name__}: {exc}"
    results.append({"name": name, "contained": not succeeded, "detail": detail})


def network():
    s = socket.socket()
    s.settimeout(3)
    s.connect(("1.1.1.1", 53))
    return True, "connected to 1.1.1.1:53"


def write_root():
    with open("/etc/sandbox_probe", "w") as f:
        f.write("x")
    return True, "wrote to /etc"


def write_model():
    with open("/model/probe_write.txt", "w") as f:
        f.write("x")
    return True, "wrote into read-only model folder"


def see_host():
    exists = os.path.exists("/Users") or os.path.exists("/mnt/c")
    return exists, "host Windows paths visible" if exists else "no host paths visible"


def root_user():
    uid = os.getuid()
    return uid == 0, f"uid={uid}"


def capabilities():
    with open("/proc/self/status") as f:
        line = next(l for l in f if l.startswith("CapEff"))
    value = line.split()[1]
    return int(value, 16) != 0, f"CapEff={value}"


def exec_from_tmp():
    path = "/tmp/probe.sh"
    with open(path, "w") as f:
        f.write("#!/bin/sh\necho ran\n")
    os.chmod(path, stat.S_IRWXU)
    out = subprocess.run([path], capture_output=True, text=True, timeout=5)
    return out.returncode == 0, f"exit={out.returncode}"


def fork_limit():
    made = 0
    pids = []
    for _ in range(100):
        try:
            pid = os.fork()
        except OSError:
            break
        if pid == 0:
            time.sleep(2)
            os._exit(0)
        pids.append(pid)
        made += 1
    for pid in pids:
        os.waitpid(pid, 0)
    return made >= 100, f"created {made} processes"


def namespaces():
    # Creating a new network namespace is a common step in escape chains.
    # Seccomp should refuse unshare outright.
    os.unshare(os.CLONE_NEWNET)
    return True, "created a new network namespace"


def core_dumps_off():
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    return soft != 0 or hard != 0, f"RLIMIT_CORE=({soft},{hard})"


def hostname_neutral():
    name = socket.gethostname()
    return name != "sandbox", f"hostname={name}"


def pip_removed():
    import importlib.util
    found = importlib.util.find_spec("pip") is not None
    return found, "pip importable" if found else "pip not present"


check("no network", network)
check("core dumps disabled", core_dumps_off)
check("hostname is neutral", hostname_neutral)
check("pip removed (no package install path)", pip_removed)
check("namespace creation blocked (seccomp)", namespaces)
check("root filesystem not writable", write_root)
check("model folder is read-only", write_model)
check("host filesystem not visible", see_host)
check("runs as non-root", root_user)
check("no Linux capabilities", capabilities)
check("cannot execute files from /tmp", exec_from_tmp)
check("process count capped", fork_limit)

# Only report.json is written to /out; everything else stays in the container.
with open("/out/report.json", "w") as f:
    json.dump(results, f, indent=2)
print(json.dumps(results))
