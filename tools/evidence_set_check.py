#!/usr/bin/env python3
"""Cold implementation of draft-krausz-verification-state-03 Section 5.3 (Evidence Pinning) and the
Section 5.4.1 evidence-set resolution step, written from the draft text alone (x402-foundation/tsc#4).
Stdlib only. Moved from -02 (tag: ecdbeb8, findings F1-F12 in examples/evidence-set-cold/FINDINGS.md) to the -03 text on
TKCollective/agentoracle-ietf-id branch dash03-cold-build-resolutions (5a71863): report-all conditions with type-check
suppression, unsupported version -> unknown, the (k) evaluation order. Readings not fixed by the text: `# READING Rn`.

    python3 tools/evidence_set_check.py receipt_payload.json [--content DIR]
        DIR holds candidate content files named by their lowercase sha256 hex OR by any name; every file
        is hashed and offered as candidate content for step (d).
    python3 tools/evidence_set_check.py --build sources.json      # issuer side: entries -> evidence_set

Exit: 0 resolved, 2 unknown, 1 malformed (gate decision = halt). Output: JSON report.
"""
from __future__ import annotations

import copy
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
# -03 5.3.2: must also denote a valid instant; seconds 00-59 (":60" not permitted).
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

RESOLVED, UNKNOWN, HALT = "resolved", "unknown", "halt"


def _valid_ts(s):
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m:
        return False
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and h <= 23 and mi <= 59 and se <= 59):
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


def _check_entry(e, i, conds):
    """5.3.2 for one entry, report-all. Returns the set of members that failed their own type/form check
    (5.4.1(a): a condition is not evaluated if any member it takes as input failed its own check)."""
    bad = set()
    if not isinstance(e, dict):
        conds.add("source_entry_not_object")
        return {"*"}
    if not _valid_ts(e.get("retrieved_at")):
        conds.add("retrieved_at_not_canonical_form"); bad.add("retrieved_at")
    pinned = e.get("pinned")
    if not isinstance(pinned, bool):
        conds.add("pinned_absent_or_not_boolean"); bad.add("pinned")
    if not isinstance(e.get("url"), str):
        conds.add("url_absent_or_not_string"); bad.add("url")
    for k in ("url", "snippet_sha256", "content_kind", "retrieved_at"):
        if isinstance(e.get(k), str) and "\x00" in e[k]:
            conds.add("member_contains_nul")
    s = e.get("snippet_sha256")
    if s is not None and not (isinstance(s, str) and HEX64.match(s)):
        conds.add("snippet_sha256_not_lowercase_hex64"); bad.add("snippet_sha256")
    ck = e.get("content_kind")
    rs = e.get("resource_sha256")
    if rs is not None and not (isinstance(rs, str) and HEX64.match(rs)):
        conds.add("resource_sha256_not_lowercase_hex64"); bad.add("resource_sha256")
    # ranges over every entry regardless of pinned; takes content_kind and resource_sha256 as input
    if ck == "full_resource" and rs is not None and "resource_sha256" not in bad:
        conds.add("resource_sha256_present_for_full_resource")
    if "pinned" in bad:
        return bad | {"snippet_sha256", "content_kind"}   # every branch rule takes pinned as input
    if pinned:
        if s is None:                                     # absent or null
            conds.add("snippet_sha256_absent_when_pinned"); bad.add("snippet_sha256")
        if ck not in CONTENT_KINDS:
            conds.add("content_kind_absent_or_invalid_when_pinned"); bad.add("content_kind")
    else:
        if "snippet_sha256" not in e:
            conds.add("snippet_sha256_member_absent"); bad.add("snippet_sha256")
        elif s is not None:
            # -03 (TK, tsc#4 5842824265): _present_when_/_absent_when_ rules are PRESENCE checks -- evaluated whatever the tested
            # member's form (a malformed pinned still suppresses them, above). So a non-hex digest on an unpinned entry reports
            # BOTH snippet_sha256_not_lowercase_hex64 and snippet_sha256_present_when_unpinned. (Was READING R1 -- superseded.)
            conds.add("snippet_sha256_present_when_unpinned")
        if ck is not None:
            conds.add("content_kind_present_when_unpinned")
        if e.get("unpinned_reason") not in UNPINNED_REASONS:
            conds.add("unpinned_reason_absent_or_invalid")
    return bad


def _same_retrieval(a, b):
    if a["url"] != b["url"] or a["retrieved_at"] != b["retrieved_at"]:
        return False
    if a["pinned"] and b["pinned"]:
        return a["snippet_sha256"] == b["snippet_sha256"] and a["content_kind"] == b["content_kind"]
    return True   # "A pinned entry and an unpinned entry sharing url and retrieved_at are ... one retrieval recorded twice"


def _int(v):
    return type(v) is int


def validate(es):
    """5.4.1 (h)-structural + (a) + (b), in the (k) order. Returns (conditions:set, derived:dict|None,
    unsupported:bool). Empty conditions and unsupported False = consistent."""
    # (k): version-independent structural checks of (h); a failure is reported alone and stops evaluation.
    if not isinstance(es, dict):
        return {"evidence_set_not_object"}, None, False
    v = es.get("evidence_set_version")
    if not isinstance(v, str):
        return {"evidence_set_version_absent_or_not_string"}, None, False
    if v != VERSION:
        return set(), None, True       # (h): unknown, every version-specific rule stops
    conds = set()
    src = es.get("sources")
    if src is None or src == []:
        conds.add("evidence_set_names_no_sources")
    elif not isinstance(src, list):
        conds.add("sources_not_array")
    if conds:
        # (a): no per-entry check and no check against len(sources); the counts, fully_pinned, root presence and
        # set-level retrieved_at all take sources as input.
        return conds, None, False
    bads = [_check_entry(e, i, conds) for i, e in enumerate(src)]
    n = len(src)
    sc = es.get("source_count", n)
    if not _int(sc) or sc != n:
        conds.add("source_count_mismatch")
    pinned_ok = all("pinned" not in b and "*" not in b for b in bads)
    p = sum(1 for e in src if isinstance(e, dict) and e.get("pinned") is True) if pinned_ok else None
    if pinned_ok:
        pc = es.get("pinned_count", p)
        if not _int(pc) or pc != p:
            conds.add("pinned_count_mismatch")
        fp = es.get("fully_pinned", p == n and n > 0)
        if fp is not (p == n and n > 0):
            conds.add("fully_pinned_mismatch")
        root = es.get("evidence_root", None)
        if p == 0 and root is not None:
            conds.add("evidence_root_present_with_no_pinned_items")
        if p > 0 and root is None:
            conds.add("evidence_root_absent_with_pinned_items")
    ts_ok = all("retrieved_at" not in b and "*" not in b for b in bads)
    if ts_ok:   # whole-check suppression: one malformed retrieved_at suppresses both set-wide rules
        least = min(_b(e["retrieved_at"]) for e in src)
        if "retrieved_at" in es and (not isinstance(es["retrieved_at"], str) or _b(es["retrieved_at"]) != least):
            conds.add("set_retrieved_at_not_bytewise_least")
        # (absent set-level retrieved_at: derived as the bytewise-least, 5.3.1 fallback)
        dup_in = {"url", "pinned", "snippet_sha256", "content_kind", "*"}
        ok = [i for i, b in enumerate(bads) if not (b & dup_in)]
        for x in range(len(ok)):
            for y in range(x + 1, len(ok)):
                if _same_retrieval(src[ok[x]], src[ok[y]]):
                    conds.add("duplicate_bound_tuple")
    if conds:
        return conds, None, False
    # (b), only if (a) reported none
    want = evidence_root(src)
    if es.get("evidence_root") is not None and es["evidence_root"] != want:
        return {"root_not_recomputable_from_sources"}, None, False
    return set(), {"source_count": n, "pinned_count": p, "fully_pinned": p == n and n > 0, "evidence_root": want}, False


def resolve(payload, held=None):
    """The evidence-set step. held: {'hashes': set of sha256 hex held, 'by_url': {url: sha256hex}}.
    Returns (token, report); token in {resolved, unknown} or HALT (malformed)."""
    held = held or {}
    if "evidence_set" not in payload:
        return UNKNOWN, {"step": "evidence_set", "resolution": UNKNOWN, "why": "no evidence_set (5.4.1 e); not a failure"}
    conds, d, unsupported = validate(payload["evidence_set"])
    if conds:
        return HALT, {"step": "evidence_set", "resolution": HALT, "gate": "halt", "conditions": sorted(conds)}
    if unsupported:
        return UNKNOWN, {"step": "evidence_set", "resolution": UNKNOWN, "reason": "evidence_set_version_unsupported"}
    by_hash, by_url = held.get("hashes", set()), held.get("by_url", {})
    items, all_match = [], True
    for e in payload["evidence_set"]["sources"]:
        if e["pinned"] and e["snippet_sha256"] in by_hash:
            items.append({"url": e["url"], "reason": "content_matches"})
        elif e["pinned"] and e["url"] in by_url:
            items.append({"url": e["url"], "reason": "content_differs"}); all_match = False
        else:
            items.append({"url": e["url"], "reason": "content_not_held"}); all_match = False
    # (i): resolved only when fully pinned, root recomputes, and every item content_matches (conjunction)
    token = RESOLVED if d["fully_pinned"] and all_match else UNKNOWN
    rep = {"step": "evidence_set", "resolution": token, **d, "items": items,
           "offline_recomputation": "performed" if token == RESOLVED else "not established"}
    if not d["fully_pinned"]:
        rep["why"] = "partial evidence set (5.4.1 c): valid, but MUST NOT be presented as satisfying offline recomputation"
    return token, rep


def build(entries):
    """Issuer side: finished source entries -> evidence_set (counts, set retrieved_at, root)."""
    entries = copy.deepcopy(entries)
    es = {"evidence_set_version": VERSION,
          "retrieved_at": min(entries, key=lambda e: _b(e["retrieved_at"]))["retrieved_at"],
          "source_count": len(entries), "pinned_count": sum(1 for e in entries if e["pinned"]),
          "fully_pinned": all(e["pinned"] for e in entries) and len(entries) > 0,
          "evidence_root": evidence_root(entries), "sources": entries}
    conds, _, _ = validate(es)
    if conds:
        raise ValueError(f"build produced a malformed evidence_set: {sorted(conds)}")
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
