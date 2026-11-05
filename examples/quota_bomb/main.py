"""Tries to fill the output folder. The sandbox should stop it at the quota
(watchdog kill) or hit the per-file size cap. Used to test the disk limits.
"""
import os

chunk = b"x" * (8 * 1024 * 1024)
for i in range(60):  # 480 MB total, well over the 200 MB run quota
    try:
        with open(f"/out/fill_{i}.bin", "wb") as f:
            f.write(chunk)
    except OSError as exc:
        print("write refused:", exc)
        break
print("finished writing")
