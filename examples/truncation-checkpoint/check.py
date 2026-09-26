#!/usr/bin/env python3
"""Hash links expose broken links, not truncation. Standard library only; deterministic.
A 10-entry hash-linked log. Three presented copies:
  full       -- intact
  tail_cut   -- the last 3 entries dropped (every remaining link still verifies)
  gap        -- one interior entry dropped (a link breaks)
Link verification alone accepts full AND tail_cut. Only a comparison with an independently retained checkpoint
(the head hash and entry count, retained outside the log's control at write time) rejects tail_cut.
    python3 check.py   -> prints the table; exits 0 iff every case matches its expected outcome."""
import hashlib, json, sys

def H(b): return hashlib.sha256(b).hexdigest()
def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()

def build(n):
    log, prev = [], "0" * 64
    for i in range(n):
        body = {"seq": i, "event": f"tool_call_{i}", "prev": prev}
        h = H(canon(body)); log.append(dict(body, hash=h)); prev = h
    return log

def links_ok(log):
    prev = "0" * 64
    for e in log:
        body = {k: e[k] for k in ("seq", "event", "prev")}
        if e["prev"] != prev or H(canon(body)) != e["hash"]: return False
        prev = e["hash"]
    return True

def matches_checkpoint(log, cp):
    return bool(log) and log[-1]["hash"] == cp["head"] and len(log) == cp["count"]

full = build(10)
checkpoint = {"head": full[-1]["hash"], "count": len(full)}      # retained OUTSIDE the log at write time (e.g. anchored / broadcast)
cases = {"full": full, "tail_cut": full[:-3], "gap": full[:4] + full[5:]}
expect = {"full": (True, True), "tail_cut": (True, False), "gap": (False, False)}
bad = 0
print(f"{'copy':9s} {'links verify':13s} {'matches checkpoint':19s}")
for name, log in cases.items():
    got = (links_ok(log), matches_checkpoint(log, checkpoint))
    bad += got != expect[name]
    print(f"{name:9s} {str(got[0]):13s} {str(got[1]):19s} {'ok' if got == expect[name] else 'UNEXPECTED'}")
print("tail_cut passes link verification and is caught only by the checkpoint." if not bad else "FAIL")
sys.exit(1 if bad else 0)
