#!/usr/bin/env python3
"""Fails when two named packages resolve a shared dependency differently.

Deliberately narrower than `cargo tree --duplicates`. A workspace of any
size has duplicates it does not control — actix pulls its own base64,
half the ecosystem is mid-migration between rand 0.8 and 0.9 — and a
check that cannot be made green is a check that gets switched off.

What matters here is that the two crates sharing the token path agree.
"""
import json, subprocess, sys

LEFT = sys.argv[1] if len(sys.argv) > 1 else "proxyauth"
RIGHT = sys.argv[2] if len(sys.argv) > 2 else "zerocrypt"
WATCH = {"chacha20poly1305", "sha2", "hkdf", "blake3", "subtle", "base64", "rand"}

meta = json.loads(subprocess.run(
    ["cargo", "metadata", "--format-version", "1"],
    capture_output=True, text=True, check=True).stdout)

by_id = {p["id"]: p for p in meta["packages"]}
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

def direct_deps(name):
    """{crate: version} for the watched direct dependencies of `name`."""
    out = {}
    for pid, pkg in by_id.items():
        if pkg["name"] != name:
            continue
        for dep in nodes.get(pid, {}).get("deps", []):
            d = by_id[dep["pkg"]]
            if d["name"] in WATCH:
                out[d["name"]] = d["version"]
    return out

left, right = direct_deps(LEFT), direct_deps(RIGHT)
if not left:
    print(f"error: package '{LEFT}' not found in the dependency graph")
    sys.exit(2)
if not right:
    print(f"error: package '{RIGHT}' not found in the dependency graph")
    sys.exit(2)

failed = False
print(f"  {'crate':<20} {LEFT:<14} {RIGHT:<14}")
for crate in sorted(WATCH):
    a, b = left.get(crate), right.get(crate)
    if a is None or b is None:
        continue
    mark = "" if a == b else "   <-- MISMATCH"
    if a != b:
        failed = True
        print(f"::error::{LEFT} uses {crate} {a}, {RIGHT} uses {b}")
    print(f"  {crate:<20} {a:<14} {b:<14}{mark}")

if failed:
    print(f"\n{LEFT} and {RIGHT} share the token path; two versions of the "
          f"same primitive means two implementations in one binary.")
    sys.exit(1)
print(f"\n{LEFT} and {RIGHT} agree on every shared cryptographic crate.")
