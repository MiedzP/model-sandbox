#!/usr/bin/env python3
"""Run an untrusted AI model or agent inside a locked-down Docker container.

Commands:
  python sandbox.py run <model_dir> [--entry main.py] [--timeout 120]
                                    [--memory 512m] [--cpus 1] [--decoy]
      Runs <model_dir>/<entry> in a sandbox. The model folder is mounted
      read-only at /model. /out is an in-memory tmpfs with a hard size and
      file-count cap, copied to runs/<run-id>/out after the run.

  python sandbox.py selftest
      Runs the bundled escape probe and reports which containment checks held.

  python sandbox.py kill
      Force-stops every running sandbox container (emergency stop).

Every run writes runs/<run-id>/log.json with the exit code, timing, limits,
and captured stdout/stderr, so you can review what a model tried to do.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import traps

HERE = Path(__file__).resolve().parent
IMAGE = "model-sandbox:latest"
LABEL = "model-sandbox=1"
SECCOMP = HERE / "seccomp.json"
RUNS = HERE / "runs"
SLOT_DIR = HERE / "slots"
# Models and exports are staged here before mounting, so the container's mount
# table shows this path instead of the Windows user profile.
STAGE_ROOT = Path(os.environ.get("MSB_STAGE", r"C:\msb-stage"))
MAX_LOG_CHARS = 200_000     # keep logs from filling the disk
MAX_STREAM_MB = 20          # stdout or stderr beyond this kills the run
MAX_OUT_MB = 200            # /out tmpfs size cap (kernel-enforced)
MAX_OUT_FILES = 5000        # /out tmpfs inode cap (kernel-enforced)
MAX_FILE_MB = 100           # per-file cap (kernel-enforced, via fsize ulimit)
MAX_CONCURRENT = 4          # slot locks; at most this many runs at once
WATCH_INTERVAL_S = 1.0


def docker(*args, check=True, timeout=None):
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def kill_container(name):
    """Kill with a time limit, so a wedged daemon can't hang the sandbox runner."""
    try:
        subprocess.run(["docker", "kill", "-s", "KILL", name],
                       capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        print(f"WARNING: 'docker kill {name}' timed out; Docker may need a restart.")


def salvage(name):
    """Copy whatever is in /out to the export mount while the container is still running.
    Needed because a tmpfs disappears with the container."""
    try:
        subprocess.run(["docker", "exec", name, "sh", "-c", "cp -a /out/. /export/ 2>/dev/null"],
                       capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        print(f"WARNING: could not salvage output from {name}.")


def ensure_docker():
    try:
        docker("info", timeout=20)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        sys.exit("Docker is not reachable. Start Docker Desktop and try again.")


def ensure_image():
    if docker("image", "inspect", IMAGE, check=False).returncode != 0:
        print("Building sandbox image (first run only)...")
        subprocess.run(["docker", "build", "-t", IMAGE, str(HERE)], check=True)


def running_sandboxes():
    return docker("ps", "-q", "--filter", f"label={LABEL}", check=False).stdout.split()


def acquire_slot():
    """Take one of MAX_CONCURRENT OS-level file locks. The check-and-claim is atomic:
    the OS grants a lock to one process only, and releases it if the process dies."""
    SLOT_DIR.mkdir(exist_ok=True)
    for i in range(MAX_CONCURRENT):
        f = open(SLOT_DIR / f"slot{i}.lock", "a+b")
        try:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                f.write(b"0")
                f.flush()
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except OSError:
            f.close()
    sys.exit(f"All {MAX_CONCURRENT} sandbox slots are busy. Wait for a run to finish or run 'kill'.")


def truncate(text):
    return text if len(text) <= MAX_LOG_CHARS else text[:MAX_LOG_CHARS] + "\n...[truncated]"


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(root):
    """Hash of every file's relative path and contents, in a fixed order."""
    import hashlib
    h = hashlib.sha256()
    for p in sorted(Path(root).rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(root)).replace("\\", "/").encode() + b"\0")
            h.update(sha256_file(p).encode() + b"\0")
    return h.hexdigest()


def image_id():
    r = docker("image", "inspect", IMAGE, "--format", "{{.Id}}", check=False)
    return r.stdout.strip() or None


# Output that Windows would run when a user double-clicks it: quarantined by renaming.
RUNNABLE_EXT = {".exe", ".dll", ".scr", ".com", ".cpl", ".msi", ".bat", ".cmd", ".ps1",
                ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk",
                ".url", ".reg", ".jar", ".app", ".dmg"}
# Scripts that are normal for code output: flagged in the log, not renamed.
SCRIPT_EXT = {".py", ".pyw", ".sh"}
# Native binary and script signatures, checked by content regardless of extension.
EXEC_MAGIC = (b"MZ", b"\x7fELF", b"#!", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def quarantine(root):
    """Rename runnable files to *.quarantined and flag scripts. Returns (renamed, flagged)."""
    renamed, flagged = [], []
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        with open(p, "rb") as f:
            head = f.read(4)
        magic = head.startswith(EXEC_MAGIC)
        rel = str(p.relative_to(root)).replace("\\", "/")
        if ext in RUNNABLE_EXT or magic:
            dst = p.with_name(p.name + ".quarantined")
            os.replace(p, dst)
            renamed.append(rel)
        elif ext in SCRIPT_EXT:
            flagged.append(rel)
    return renamed, flagged


# Windows device names. A file called CON or NUL is a device on Windows, not a file.
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL",
                *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
WIN_BAD_CHARS = '<>:"|?*'


def safe_name(name):
    # U+F000-U+F0FF is the private-use range Windows/WSL use to stand in for characters
    # like ':' that a Windows filename cannot contain.
    cleaned = "".join(
        "_" if (c in WIN_BAD_CHARS or ord(c) < 32 or 0xF000 <= ord(c) <= 0xF0FF) else c
        for c in name
    )
    cleaned = cleaned.rstrip(" .")  # Windows silently strips trailing dots and spaces
    if not cleaned:
        cleaned = "_"
    if cleaned.split(".")[0].upper() in WIN_RESERVED:
        cleaned = "_" + cleaned
    return cleaned


def sanitize_tree(root):
    """Rename anything under root that Windows would misread. Returns [old, new] pairs.

    Paths are built by hand and never passed through abspath, because abspath
    strips trailing dots and spaces ("dot. " would become "dot") and the \\\\?\\
    prefix stops Windows from treating CON or NUL as devices.
    """
    base = os.path.abspath(root)
    if os.name == "nt":
        base = "\\\\?\\" + base
    sep = "\\" if os.name == "nt" else "/"
    renamed = []

    def visit(d):
        for entry in list(os.scandir(d)):
            if entry.is_dir(follow_symlinks=False):
                visit(d + sep + entry.name)
            new = safe_name(entry.name)
            if new == entry.name:
                continue
            dst = d + sep + new
            n = 1
            while os.path.lexists(dst):
                dst = d + sep + f"{new}_{n}"
                n += 1
            os.rename(d + sep + entry.name, dst)
            renamed.append([(d + sep + entry.name)[len(base):].lstrip(sep), dst[len(base):].lstrip(sep)])

    visit(base)
    return renamed


def run_model(model_dir, entry, timeout, memory, cpus, decoy=False):
    model_dir = Path(model_dir).resolve()
    entry_path = (model_dir / entry).resolve()
    if model_dir not in entry_path.parents or not entry_path.is_file():
        sys.exit(f"Entry must be a file inside the model folder: {model_dir / entry}")

    ensure_docker()
    slot = acquire_slot()
    try:
        return _run_model(model_dir, entry, timeout, memory, cpus, decoy)
    finally:
        slot.close()  # releases the slot lock


def _run_model(model_dir, entry, timeout, memory, cpus, decoy):
    # Secondary check: catches sandboxes started outside this runner (e.g. orphans).
    active = running_sandboxes()
    if len(active) >= MAX_CONCURRENT:
        sys.exit(f"{len(active)} sandboxes already running (limit {MAX_CONCURRENT}). Wait or run 'kill'.")
    ensure_image()

    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True)
    out_dir = run_dir / "out"  # final location, filled after the run

    stage = STAGE_ROOT / run_id
    stage_model = stage / "model"
    stage_export = stage / "export"
    stage_export.mkdir(parents=True)
    shutil.copytree(model_dir, stage_model,
                    ignore=shutil.ignore_patterns("runs", ".git", "__pycache__"))
    model_sha = tree_hash(stage_model)  # hash of exactly what the container will run
    audit = {
        "image_id": image_id(),
        "seccomp_sha256": sha256_file(SECCOMP),
        "model_tree_sha256": model_sha,
    }
    stage_decoy = stage / "decoy"
    decoy_manifest = traps.make_decoy(stage_decoy) if decoy else None
    name = f"msb-{run_id}"
    file_bytes = MAX_FILE_MB * 1024 * 1024

    limits = {
        "network": "none",
        "root_fs": "read-only",
        "seccomp": "allowlist (seccomp.json)",
        "memory": memory,
        "cpus": cpus,
        "pids": 64,
        "out": f"tmpfs, {MAX_OUT_MB} MB and {MAX_OUT_FILES} inodes (kernel-enforced)",
        "max_file_mb": MAX_FILE_MB,
        "timeout_s": timeout,
        "user": "65534:65534",
        "capabilities": "none",
    }

    # The model runs as a child of sh, which copies /out to /export after it exits,
    # so output is kept even if the model exits with an error.
    shell_script = 'python -E "$1"; rc=$?; cp -a /out/. /export/ 2>/dev/null; exit $rc'
    cmd = [
        "run", "--rm", "--name", name, "--label", LABEL,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs", f"/out:rw,noexec,nosuid,mode=0755,uid=65534,gid=65534,"
                   f"size={MAX_OUT_MB}m,nr_inodes={MAX_OUT_FILES}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={SECCOMP}",
        "--pids-limit", str(limits["pids"]),
        "--memory", memory,
        "--memory-swap", memory,
        "--cpus", str(cpus),
        "--ulimit", f"fsize={file_bytes}:{file_bytes}",
        "--ulimit", "nofile=256:256",
        "--ulimit", "core=0:0",          # no core dumps (they can contain memory contents)
        "--ipc", "none",
        "--cgroupns", "private",
        "--hostname", "sandbox",         # don't leak the host name
        "--user", limits["user"],
        "-v", f"{stage_model}:/model:ro",
        "-v", f"{stage_export}:/export:rw",
        *(["-v", f"{stage_decoy}:/decoy:ro"] if decoy else []),
        "-w", "/out",
        IMAGE,
        "sh", "-c", shell_script, "sh", f"/model/{entry}",
    ]

    started = time.time()
    stop_reason = {"value": None}
    done = threading.Event()

    def watchdog():
        while not done.wait(WATCH_INTERVAL_S):
            if not stop_reason["value"] and time.time() - started > timeout:
                stop_reason["value"] = "timeout"
            if stop_reason["value"]:
                salvage(name)          # keep partial output before the kill
                kill_container(name)
                return

    # Stream stdout/stderr instead of buffering everything. Only the first
    # MAX_LOG_CHARS of each is kept; a stream that grows past MAX_STREAM_MB kills the run.
    proc = subprocess.Popen(
        ["docker", *cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    kept = {"stdout": [], "stderr": []}
    kept_chars = {"stdout": 0, "stderr": 0}
    total_bytes = {"stdout": 0, "stderr": 0}
    lock = threading.Lock()
    max_stream = MAX_STREAM_MB * 1024 * 1024

    def pump(key, stream):
        for chunk in iter(lambda: stream.read(65536), ""):
            with lock:
                total_bytes[key] += len(chunk.encode("utf-8", errors="replace"))
                if kept_chars[key] < MAX_LOG_CHARS:
                    kept[key].append(chunk)
                    kept_chars[key] += len(chunk)
                over = total_bytes[key] > max_stream
            # Never block here: the watchdog performs the kill. Keep draining the
            # pipe either way so the container can't stall on a full buffer.
            if over and not stop_reason["value"]:
                stop_reason["value"] = f"{key} over {MAX_STREAM_MB} MB"
        stream.close()

    pumps = [threading.Thread(target=pump, args=(k, s), daemon=True)
             for k, s in (("stdout", proc.stdout), ("stderr", proc.stderr))]
    watcher = threading.Thread(target=watchdog, daemon=True)
    for t in pumps:
        t.start()
    watcher.start()
    try:
        proc.wait(timeout=timeout + 60)
    except subprocess.TimeoutExpired:
        stop_reason["value"] = stop_reason["value"] or "docker did not exit"
        salvage(name)
        kill_container(name)
        proc.kill()
        proc.wait()
    finally:
        done.set()
        for t in pumps:
            t.join(timeout=10)
        watcher.join(timeout=5)

    stdout = "".join(kept["stdout"])
    stderr = "".join(kept["stderr"])
    exit_code = proc.returncode
    timed_out = stop_reason["value"] == "timeout"
    duration = round(time.time() - started, 2)

    # Make names safe for Windows first (the export is a host folder), then move it into the run.
    renamed = sanitize_tree(stage_export)
    shutil.move(str(stage_export), str(out_dir))
    shutil.rmtree(stage, ignore_errors=True)
    quarantined, flagged = quarantine(out_dir)

    # Canary check: did the model repeat a decoy token in stdout, stderr, or its output?
    decoy_report = None
    if decoy_manifest:
        texts = [stdout, stderr]
        for p in out_dir.rglob("*"):
            if p.is_file() and p.stat().st_size <= 1024 * 1024:
                try:
                    texts.append(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        decoy_report = {
            "manifest": decoy_manifest,
            "canaries_seen": traps.find_canaries_seen(decoy_manifest, texts),
        }

    files = sorted(str(p.relative_to(out_dir)) for p in out_dir.rglob("*") if p.is_file())
    log = {
        "run_id": run_id,
        "model_dir": str(model_dir),
        "entry": entry,
        "limits": limits,
        "duration_s": duration,
        "timed_out": timed_out,
        "stop_reason": stop_reason["value"],
        "exit_code": exit_code,
        "stdout_bytes": total_bytes["stdout"],
        "stderr_bytes": total_bytes["stderr"],
        "audit": audit,
        "renamed_for_windows": renamed,
        "quarantined": quarantined,
        "scripts_flagged": flagged,
        "decoy": decoy_report,
        "output_files": files,
        "stdout": truncate(stdout),
        "stderr": truncate(stderr),
    }
    (run_dir / "log.json").write_text(json.dumps(log, indent=2), encoding="utf-8")

    if stop_reason["value"]:
        status = f"KILLED ({stop_reason['value']})"
    else:
        status = f"exit code {exit_code}"
    print(f"[{run_id}] {status} after {duration}s")
    print(f"Log:    {run_dir / 'log.json'}")
    print(f"Output: {out_dir}")
    return 0 if exit_code == 0 else 1


def selftest():
    ensure_docker()
    probe = HERE / "examples" / "escape_probe"
    run_model(probe, "main.py", timeout=120, memory="512m", cpus=1)
    # Read the most recent run's report.
    latest = max(RUNS.glob("*/log.json"), key=lambda p: p.stat().st_mtime)
    log = json.loads(latest.read_text(encoding="utf-8"))
    report_file = Path(latest).parent / "out" / "report.json"
    if not report_file.exists():
        sys.exit("Probe produced no report. See the log stderr:\n" + log["stderr"])
    checks = json.loads(report_file.read_text(encoding="utf-8"))
    held = 0
    for c in checks:
        mark = "CONTAINED" if c["contained"] else "ESCAPED  "
        held += c["contained"]
        print(f"  {mark}  {c['name']}: {c['detail']}")
    print(f"\n{held}/{len(checks)} containment checks held.")
    return 0 if held == len(checks) else 1


def kill_all():
    ensure_docker()
    ids = docker("ps", "-q", "--filter", f"label={LABEL}", check=False).stdout.split()
    if not ids:
        print("No sandbox containers running.")
        return 0
    docker("kill", *ids, check=False)
    print(f"Killed {len(ids)} sandbox container(s).")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a model in the sandbox")
    r.add_argument("model_dir")
    r.add_argument("--entry", default="main.py")
    r.add_argument("--timeout", type=int, default=120, help="seconds before the container is killed")
    r.add_argument("--memory", default="512m", help="includes the /out tmpfs (up to 200 MB)")
    r.add_argument("--cpus", type=float, default=1.0)
    r.add_argument("--decoy", action="store_true",
                   help="mount a Markov loop-trap decoy tree read-only at /decoy and check for canaries")

    sub.add_parser("selftest", help="verify containment with the bundled probe")
    sub.add_parser("kill", help="stop all running sandbox containers")

    args = parser.parse_args()
    if args.cmd == "run":
        return run_model(args.model_dir, args.entry, args.timeout, args.memory, args.cpus, args.decoy)
    if args.cmd == "selftest":
        return selftest()
    return kill_all()


if __name__ == "__main__":
    sys.exit(main())
