#!/usr/bin/env python3
"""Fail-closed check of an append-only, hash-chained session history (microsoft/autogen#7353).

Chain rule (the public invinoveritas ledger's, used for the real vectors):
    content_hash = sha256( JSON(record, sort_keys, separators=(",",":"), ensure_ascii=False) as UTF-8 )
    head_hash    = sha256( f"{content_hash}|{prev_head_hash}" )
An EXTERNAL HEAD is {entry, head_hash} held by someone other than the log's writer (a relay copy, an observer's
saved head). Without one, removal from the END of the log cannot be seen from the log alone.

Result (exit code): PASS (0) / FAIL (1) / CANNOT_ESTABLISH (2).
  FAIL              any content hash does not recompute, any link breaks (splice / reorder / tamper), entry numbers are
                    not consecutive, or an external head contradicts the log (log shorter than a head someone holds,
                    or a different head_hash for the same entry = equivocation).
  CANNOT_ESTABLISH  the log is internally consistent but no external head was supplied, so truncation of the tail
                    is undetectable. Never reported as PASS.
  PASS              internally consistent AND every supplied external head is matched by the log at that entry.
                    Scope: complete up to the newest external head supplied -- not beyond it.

    python3 tools/session_chain_check.py chain.json [external_heads.json]
"""
import hashlib
import json
import sys

PASS, FAIL, CANNOT = "PASS", "FAIL", "CANNOT_ESTABLISH"


def content_hash(record):
    return hashlib.sha256(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def check(entries, external_heads=None):
    """-> (result, [reasons])"""
    external_heads = external_heads or []
    why = []
    if not entries:
        return CANNOT, ["empty log"]
    prev = entries[0]["chain"]["prev_head_hash"]
    for i, e in enumerate(entries):
        c = e["chain"]
        if i and e["entry"] != entries[i - 1]["entry"] + 1:
            why.append(f"entry numbers not consecutive at position {i}: {entries[i - 1]['entry']} -> {e['entry']}")
        if content_hash(e["record"]) != c["content_hash"]:
            why.append(f"entry {e['entry']}: content_hash does not recompute (record altered)")
        if c["prev_head_hash"] != prev:
            why.append(f"entry {e['entry']}: prev_head_hash does not link to the previous head (splice or reorder)")
        if hashlib.sha256(f"{c['content_hash']}|{c['prev_head_hash']}".encode("utf-8")).hexdigest() != c["head_hash"]:
            why.append(f"entry {e['entry']}: head_hash does not recompute")
        prev = c["head_hash"]
    if why:
        return FAIL, why
    by_entry = {e["entry"]: e["chain"]["head_hash"] for e in entries}
    last = entries[-1]["entry"]
    for h in external_heads:
        n, hh = h["entry"], h["head_hash"]
        if n > last:
            why.append(f"external head for entry {n} exists but the log ends at {last} (truncated)")
        elif n in by_entry and by_entry[n] != hh:
            why.append(f"external head for entry {n} differs from the log's head (equivocation)")
        elif n not in by_entry:
            why.append(f"external head for entry {n} precedes this log segment (cannot compare)")
    if any("truncated" in w or "equivocation" in w for w in why):
        return FAIL, why
    comparable = [h for h in external_heads if h["entry"] in by_entry]
    if not comparable:
        return CANNOT, why + ["internally consistent, but no comparable external head: removal of the tail is undetectable"]
    newest = max(h["entry"] for h in comparable)
    return PASS, why + [f"consistent, and complete up to entry {newest} (the newest external head supplied); nothing is established beyond it"]


def main(a):
    entries = json.load(open(a[0]))["entries"]
    heads = json.load(open(a[1]))["external_heads"] if len(a) > 1 else []
    res, why = check(entries, heads)
    print(res)
    for w in why:
        print("  -", w)
    return {PASS: 0, FAIL: 1, CANNOT: 2}[res]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
