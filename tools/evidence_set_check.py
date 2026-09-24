#!/usr/bin/env python3
"""Cold implementation of draft-krausz-verification-state-02 Section 5.3 (Evidence Pinning) and the
Section 5.4.1 evidence-set resolution step, written from the draft text alone (x402-foundation/tsc#4).
Stdlib only. Where the text left a choice open, the choice made here is marked `# FINDING Fn` and
listed in examples/evidence-set-cold/FINDINGS.md -- those are findings against the text, not settled readings.

    python3 tools/evidence_set_check.py receipt_payload.json [--content DIR]
        DIR holds candidate content files named by their lowercase sha256 hex OR by any name; every file
        is hashed and offered as candidate content for step (d).
    python3 tools/evidence_set_check.py --build sources.json      # issuer side: entries -> evidence_set

Exit: 0 resolved, 2 unknown, 1 malformed (gate decision = halt). Output: JSON report.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

VERSION = "ao-evidence-set-v1"
LEAF_PREFIX = b"ao-evidence-leaf-v2"
NODE_PREFIX = b"ao-evidence-node-v1"
CONTENT_KINDS = ("snippet", "excerpt", "full_resource")
UNPINNED_REASONS = ("no_content_returned", "provider_metadata_only")
# 5.3.2: "UTC with the Z designator and exactly three fractional-second digits".
# FINDING F6: the text fixes the lexical form but not whether the date/time must also be a valid instant
# (2026-02-30T25:61:00.000Z). We require a valid calendar date and time (seconds 00-60 per RFC 3339 leap second).
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

RESOLVED, UNKNOWN, HALT = "resolved", "unknown", "halt"


class Malformed(Exception):
    def __init__(self, condition, detail=""):
        super().__init__(condition)
        self.condition, self.detail = condition, detail


def _valid_ts(s):
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m:
        return False
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and h <= 23 and mi <= 59 and se <= 60):
        return False
    dim = [31, 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return 1 <= d <= dim


def _b(s):
    return s.encode("utf-8")


def leaf(e):
    return hashlib.sha256(LEAF_PREFIX + b"\x00" + _b(e["url"]) + b"\x00" + _b(e["snippet_sha256"]) + b"\x00"
                          + _b(e["content_kind"]) + b"\x00" + _b(e["retrieved_at"])).digest()


def node(left, right):
    return hashlib.sha256(NODE_PREFIX + b"\x00" + left + b"\x00" + right).digest()


def sort_key(e):
    return (_b(e["url"]), _b(e["snippet_sha256"]), _b(e["content_kind"]), _b(e["retrieved_at"]))


def evidence_root(sources):
    """5.3.3: Merkle root over pinned items only, canonical order, odd node promoted (never duplicated),
    single item = its leaf, empty -> None."""
    pinned = sorted((e for e in sources if e.get("pinned") is True), key=sort_key)
    level = [leaf(e) for e in pinned]
    if not level:
        return None
    while len(level) > 1:
        nxt = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def _check_entry(e, i):
    if not isinstance(e, dict):
        raise Malformed("source_entry_not_object", f"sources[{i}]")          # FINDING F1: no named condition
    # retrieved_at form: "evaluated before any branch on pinned"
    if not _valid_ts(e.get("retrieved_at")):
        raise Malformed("retrieved_at_not_canonical_form", f"sources[{i}]")
    if not isinstance(e.get("pinned"), bool):
        raise Malformed("pinned_absent_or_not_boolean", f"sources[{i}]")
    url = e.get("url")
    if not isinstance(url, str):
        raise Malformed("url_absent_or_not_string", f"sources[{i}]")        # FINDING F1
    # 5.3.3 "No member may contain an octet 0x00" -- FINDING F5: stated as a fact, not a rule with a condition.
    # A JSON string CAN carry U+0000, so we enforce it as malformed.
    for k in ("url", "snippet_sha256", "content_kind", "retrieved_at"):
        if isinstance(e.get(k), str) and "\x00" in e[k]:
            raise Malformed("member_contains_nul", f"sources[{i}].{k}")      # FINDING F5
    ck = e.get("content_kind")
    rs = e.get("resource_sha256")
    # resource_sha256 rule "ranges over every entry regardless of pinned"
    if ck == "full_resource" and rs is not None:
        raise Malformed("snippet_digest_present_for_full_resource", f"sources[{i}]")   # FINDING F8 (name)
    if "snippet_sha256" not in e:
        # REQUIRED member (string or null). For a pinned entry 5.4.1(b) names the condition.
        if e["pinned"]:
            raise Malformed("snippet_sha256_absent_when_pinned", f"sources[{i}]")
        raise Malformed("snippet_sha256_member_absent", f"sources[{i}]")     # FINDING F1
    s = e["snippet_sha256"]
    if e["pinned"]:
        if s is None:
            # FINDING F3: 5.4.1(b) gates this check on evidence_root being non-null; we apply it unconditionally.
            raise Malformed("snippet_sha256_absent_when_pinned", f"sources[{i}]")
        if not (isinstance(s, str) and HEX64.match(s)):
            raise Malformed("snippet_sha256_not_lowercase_hex64", f"sources[{i}]")   # FINDING F1
        if ck not in CONTENT_KINDS:
            raise Malformed("content_kind_absent_or_invalid_when_pinned", f"sources[{i}]")  # FINDING F1
    else:
        if s is not None:
            # FINDING F4: "or null if not pinned" -- we read a digest on an unpinned entry as malformed (if bytes
            # were held, the possession rule says it must be pinned).
            raise Malformed("snippet_sha256_present_when_unpinned", f"sources[{i}]")
        if ck is not None:
            raise Malformed("content_kind_present_when_unpinned", f"sources[{i}]")    # FINDING F1
        if e.get("unpinned_reason") not in UNPINNED_REASONS:
            raise Malformed("unpinned_reason_absent_or_invalid", f"sources[{i}]")     # FINDING F1 (text: "malformed; halt")
    if rs is not None and not (isinstance(rs, str) and HEX64.match(rs)):
        raise Malformed("resource_sha256_not_lowercase_hex64", f"sources[{i}]")       # FINDING F1


def _same_retrieval(a, b):
    if a["url"] != b["url"] or a["retrieved_at"] != b["retrieved_at"]:
        return False
    if a["pinned"] and b["pinned"]:
        return a["snippet_sha256"] == b["snippet_sha256"] and a["content_kind"] == b["content_kind"]
    return True   # "A pinned entry and an unpinned entry sharing url and retrieved_at are ... one retrieval recorded twice"


def validate(es):
    """5.4.1(a)+(b). Returns derived counts; raises Malformed."""
    if not isinstance(es, dict):
        raise Malformed("evidence_set_not_object")                          # FINDING F1
    if es.get("evidence_set_version") != VERSION:
        raise Malformed("evidence_set_version_unrecognized")                 # FINDING F7
    src = es.get("sources")
    if not isinstance(src, list) or len(src) == 0:
        raise Malformed("evidence_set_names_no_sources")                     # FINDING F9 (absent/non-array folded in)
    for i, e in enumerate(src):
        _check_entry(e, i)
    for i in range(len(src)):
        for j in range(i + 1, len(src)):
            if _same_retrieval(src[i], src[j]):
                raise Malformed("duplicate_bound_tuple", f"sources[{i}] and sources[{j}]")
    n, p = len(src), sum(1 for e in src if e["pinned"])
    sc = es.get("source_count", n)
    pc = es.get("pinned_count", p)
    if sc != n or type(sc) is not int:
        raise Malformed("evidence_set_names_no_sources" if sc == 0 else "source_count_mismatch")   # FINDING F2
    if pc != p or type(pc) is not int:
        raise Malformed("pinned_count_mismatch")                               # FINDING F2
    fp = es.get("fully_pinned", p == n and n > 0)
    if fp is not (p == n and n > 0):
        raise Malformed("fully_pinned_mismatch")                               # FINDING F2
    least = min((_b(e["retrieved_at"]) for e in src))
    if "retrieved_at" in es:
        if not isinstance(es["retrieved_at"], str) or _b(es["retrieved_at"]) != least:
            raise Malformed("set_retrieved_at_not_bytewise_least")
    else:
        pass   # FINDING F10: retrieved_at has no stated fallback when absent (the counts do); we derive it.
    root = es.get("evidence_root", None)
    want = evidence_root(src)
    if p == 0:
        if root is not None:
            raise Malformed("evidence_root_present_with_no_pinned_items")     # FINDING F2
    else:
        if root is None:
            raise Malformed("evidence_root_absent_with_pinned_items")         # FINDING F2 / F3
        if root != want:
            raise Malformed("root_not_recomputable_from_sources")
    return {"source_count": n, "pinned_count": p, "fully_pinned": p == n and n > 0, "evidence_root": want}


def resolve(payload, held=None):
    """The evidence-set step. held: dict sha256hex -> True for candidate content the verifier holds, plus
    optional 'by_url': {url: sha256hex} for content held for a URL whose digest differs.
    Returns (token, report). token in {resolved, unknown} or HALT for malformed."""
    held = held or {}
    if "evidence_set" not in payload:
        return UNKNOWN, {"step": "evidence_set", "resolution": UNKNOWN, "why": "no evidence_set (5.4.1 e); not a failure"}
    try:
        d = validate(payload["evidence_set"])
    except Malformed as m:
        return HALT, {"step": "evidence_set", "resolution": HALT, "gate": "halt", "condition": m.condition, "detail": m.detail}
    by_hash, by_url = held.get("hashes", set()), held.get("by_url", {})
    items, all_match = [], True
    for e in payload["evidence_set"]["sources"]:
        if not e["pinned"]:
            items.append({"url": e["url"], "reason": "content_not_held"}); all_match = False; continue
        if e["snippet_sha256"] in by_hash:
            items.append({"url": e["url"], "reason": "content_matches"})     # FINDING F11: no token named for a match
        elif e["url"] in by_url:
            items.append({"url": e["url"], "reason": "content_differs"}); all_match = False
        else:
            items.append({"url": e["url"], "reason": "content_not_held"}); all_match = False
    # FINDING F12: "resolved" is defined only as "the step's evidence requirements are met". We resolve only when
    # the set is fully pinned, the root recomputes, AND the verifier held matching bytes for every item -- i.e.
    # offline recomputation was actually performed. A fully pinned set whose content we do not hold is unknown.
    token = RESOLVED if d["fully_pinned"] and all_match else UNKNOWN
    rep = {"step": "evidence_set", "resolution": token, **d, "items": items,
           "offline_recomputation": "performed" if token == RESOLVED else "not established"}
    if not d["fully_pinned"]:
        rep["why"] = "partial evidence set (5.4.1 c): valid, but MUST NOT be presented as satisfying offline recomputation"
    return token, rep


def build(entries):
    """Issuer side: finished source entries -> evidence_set (counts, set retrieved_at, root)."""
    es = {"evidence_set_version": VERSION,
          "retrieved_at": min(entries, key=lambda e: _b(e["retrieved_at"]))["retrieved_at"],
          "source_count": len(entries), "pinned_count": sum(1 for e in entries if e["pinned"]),
          "fully_pinned": all(e["pinned"] for e in entries) and len(entries) > 0,
          "evidence_root": evidence_root(entries), "sources": entries}
    validate(es)
    return es


def main(a):
    if "--build" in a:
        print(json.dumps(build(json.load(open(a[a.index("--build") + 1]))), indent=1))
        return 0
    payload = json.load(open(a[0]))
    held = {"hashes": set(), "by_url": {}}
    if "--content" in a:
        d = a[a.index("--content") + 1]
        for f in os.listdir(d):
            held["hashes"].add(hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest())
        m = os.path.join(d, "_urls.json")      # optional {url: filename} so a differing file is reported as content_differs
        if os.path.exists(m):
            for u, f in json.load(open(m)).items():
                held["by_url"][u] = hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest()
    token, rep = resolve(payload, held)
    print(json.dumps(rep, indent=1))
    return {RESOLVED: 0, UNKNOWN: 2, HALT: 1}[token]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
