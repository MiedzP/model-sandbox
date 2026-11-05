# Model Sandbox

Runs AI models and agents you design inside a locked-down Docker container.

## Setup

1. Start **Docker Desktop**.
2. Run the containment self-test (builds the image on first run):

   ```
   python C:\Users\mcpag\model-sandbox\sandbox.py selftest
   ```

   Every check should say `CONTAINED`.

## Running a model

Put your model in its own folder with an entry script, for example `my_model\main.py`:

```
python C:\Users\mcpag\model-sandbox\sandbox.py run C:\path\to\my_model --entry main.py --timeout 60 --memory 512m
```

- The model folder is mounted **read-only** at `/model`.
- The only writable location is `/out`. Save results there. Afterwards they are in `runs\<run-id>\out\`.
- Each run writes `runs\<run-id>\log.json` with stdout, stderr, exit code, duration, and limits.
- If the model needs third-party packages, add them to the `Dockerfile` and rebuild with `docker build -t model-sandbox:latest C:\Users\mcpag\model-sandbox`.

## Emergency stop

```
python C:\Users\mcpag\model-sandbox\sandbox.py kill
```

## What is enforced

| Control | Setting |
|---|---|
| Network | `--network none` (no internet, no LAN) |
| Filesystem | read-only root, model folder read-only, `/tmp` is noexec |
| Privileges | runs as uid 65534, all Linux capabilities dropped, no-new-privileges |
| Resources | memory cap, CPU cap, 64-process cap, wall-clock timeout (container is killed) |
| Host access | only the model folder and one output folder are mounted |

## Limits to know about

- Containers share the host's Linux kernel. A kernel exploit could in principle escape. For code you think might be actively hostile, add [gVisor](https://gvisor.dev/) or run the sandbox inside a separate VM (for example a dedicated WSL2 distro with no mounts to your real files).
- The model's *outputs* are untrusted. Review `log.json` and anything in `out\` before you use them.
- Network-free means models that call hosted APIs will fail. If you need API access, allow only that endpoint with a proxy and do not open general network access.

## Markov loop-trap decoy (`--decoy`)

```
python sandbox.py run <model_dir> --decoy
```

Mounts a generated, read-only tree at `/decoy`: an archive of 12 Markov-text
parts. Each part links to the next, and part 11 links back to part 0, so an agent
that follows links loops forever. Every part carries a unique `CANARY-...` token.
After the run, the log's `decoy.canaries_seen` lists any token that appears in
stdout, stderr, or the output folder. The manifest is kept in the log, not in the
mounted tree, so the model can't read the canary map.

## Other behavior

- **Staging:** models and output are copied to `C:\msb-stage\<run-id>` before mounting, so the container never sees your user profile path. Set `MSB_STAGE` to change the location.
- **Stream cap:** stdout or stderr over 20 MB kills the run. The log keeps the first 200 KB of each.
- **Windows names:** after each run, reserved or unsafe names (`CON`, `NUL`, `aux.txt`, `dot. `, names with ':' stand-ins) are renamed. Renames are listed in `renamed_for_windows`.
- **Kill path:** kills use `docker kill -s KILL` with a 20-second limit, and warn if Docker doesn't respond.

## Output quota and concurrency (current behavior)

- **Output quota is kernel-enforced.** `/out` is a tmpfs capped at 200 MB and 5,000 inodes. Writes past the cap fail with "No space left on device" and nothing overshoots. The tmpfs counts against `--memory`, so keep the memory limit above 200 MB plus what the model uses.
- **Copy-out.** The container's shell copies `/out` to an export folder when the model exits. If the run is killed for a timeout or stream limit, the runner first copies `/out` out with `docker exec`, so partial output is kept.
- **Concurrency is a real lock.** Each run holds one of 4 OS-level slot locks in `slots\` for its whole life. A launch that finds all slots busy is refused. The lock is released automatically if the runner crashes.
- **Seccomp allows `vfork`.** Shells use `vfork` to start subprocesses, so `sh -c` needs it.

## Hardening added in this round

- **Audit trail.** Each `log.json` records the image ID, a hash of the seccomp profile, and a hash of the model folder as it was copied, so a run can be reproduced and checked.
- **Output quarantine.** After a run, any file Windows would execute on double-click (`.exe`, `.bat`, `.ps1`, `.vbs`, `.js`, `.lnk`, and similar) and any file whose contents are a native binary or a shebang script is renamed to `*.quarantined`. Scripts such as `.py` and `.sh` are listed in `scripts_flagged` but not renamed.
- **No pip in the image.** Models can't install packages at runtime. Add dependencies to the image before pip is removed (see the Dockerfile).
- **No core dumps, private cgroup namespace, neutral hostname.** The self-test checks these.
- **Not available here:** gVisor (`runsc`) isn't installed on this Docker Desktop, so kernel-level isolation is still the shared Linux kernel.
