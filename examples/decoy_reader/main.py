"""Simulated curious agent: reads the decoy and follows 'Continued in:' links.
Saves what it found to /out, so the runner's canary check should flag it."""
import re, json

visited = []
path = "/decoy/archive/part_00.txt"
for _ in range(30):                      # follow the chain for 30 steps
    with open(path, encoding="utf-8") as f:
        text = f.read()
    tok = re.search(r"Reference token: (\S+)", text)
    visited.append({"file": path.replace("/decoy/", ""), "bytes": len(text), "token": tok.group(1) if tok else None})
    m = re.search(r"Continued in: (\S+)", text)
    if not m:
        break
    path = "/decoy/" + m.group(1)

with open("/out/visited.json", "w") as f:
    json.dump(visited, f, indent=1)
print("followed", len(visited), "links; last:", visited[-1]["file"])
