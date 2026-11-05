"""Ordinary workload. Confirms normal Python still runs under the seccomp allowlist.
Writes its result to /out/result.txt.
"""
import concurrent.futures
import json
import math
import random

def work(n):
    return sum(math.sqrt(i) for i in range(n))

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    totals = list(pool.map(work, [10_000, 20_000, 30_000, 40_000]))

with open("/out/result.txt", "w") as f:
    json.dump({"totals": [round(t, 3) for t in totals], "sample": random.random()}, f, indent=2)

print("ok", len(totals), "tasks")
