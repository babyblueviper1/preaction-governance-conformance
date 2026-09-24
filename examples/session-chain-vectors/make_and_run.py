#!/usr/bin/env python3
"""Builds every variant from base_chain.json (REAL public ledger entries 255-262) and checks each against its expected result.
    python3 examples/session-chain-vectors/make_and_run.py      # exit 0 iff every vector gives its expected result
"""
import copy, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import session_chain_check as S

base = json.load(open(os.path.join(HERE, "base_chain.json")))["entries"]
head = lambda n: {"entry": n, "head_hash": next(e["chain"]["head_hash"] for e in base if e["entry"] == n)}
E = lambda *ns: [copy.deepcopy(e) for n in ns for e in base if e["entry"] == n]


def tampered():
    x = E(*range(255, 263)); x[5]["record"]["title"] = x[5]["record"].get("title", "") + " (edited)"; return x


def forged_relink():
    # splice 259 out AND re-link 260 onto 258 -- only possible for the log's writer (needs no key here: the chain is unsigned)
    x = E(255, 256, 257, 258, 260, 261, 262)
    x[4]["chain"]["prev_head_hash"] = x[3]["chain"]["head_hash"]
    import hashlib
    prev = x[3]["chain"]["head_hash"]
    for e in x[4:]:
        e["chain"]["prev_head_hash"] = prev
        e["chain"]["head_hash"] = hashlib.sha256(f"{e['chain']['content_hash']}|{prev}".encode()).hexdigest()
        prev = e["chain"]["head_hash"]
    return x


def full_rewrite():
    # the WRITER drops 259, renumbers 260..262 -> 259..261 (inside the records too) and recomputes every hash:
    # internally perfect, so nothing in the log alone can catch it
    import hashlib
    x = E(255, 256, 257, 258, 260, 261, 262)
    prev = x[3]["chain"]["head_hash"]
    for k, e in enumerate(x[4:]):
        e["entry"] = 259 + k
        if "entry" in e["record"]:
            e["record"]["entry"] = 259 + k
        e["chain"]["content_hash"] = S.content_hash(e["record"])
        e["chain"]["prev_head_hash"] = prev
        e["chain"]["head_hash"] = hashlib.sha256(f"{e['chain']['content_hash']}|{prev}".encode()).hexdigest()
        prev = e["chain"]["head_hash"]
    return x


V = [  # (id, entries, external heads, expected, why)
    ("base_with_head", E(*range(255, 263)), [head(262)], S.PASS, "consistent and matches an externally held head"),
    ("base_no_head", E(*range(255, 263)), [], S.CANNOT, "consistent, but without an external head tail removal is invisible"),
    ("splice_259", E(255, 256, 257, 258, 260, 261, 262), [], S.FAIL, "a removed middle entry breaks the link (no head needed)"),
    ("reorder_258_259", E(255, 256, 257, 259, 258, 260, 261, 262), [], S.FAIL, "swapped order breaks the link"),
    ("tamper_260", tampered(), [head(262)], S.FAIL, "an edited record no longer recomputes its content_hash"),
    ("truncate_with_later_head", E(*range(255, 261)), [head(262)], S.FAIL, "log ends at 260 but a head for 262 is held elsewhere"),
    ("truncate_no_head", E(*range(255, 261)), [], S.CANNOT, "the case that must NOT pass: tail removal, nothing external"),
    ("truncate_with_older_head", E(*range(255, 261)), [head(258)], S.PASS, "complete up to 258 only -- the scope line says so"),
    ("equivocation", E(*range(255, 263)), [{"entry": 262, "head_hash": "00" * 32}], S.FAIL, "a different head for the same entry"),
    ("writer_relinks_after_splice_no_head", forged_relink(), [], S.FAIL,
     "the writer re-links around a removed entry: caught only because entry numbers skip 258->260"),
    ("writer_relinks_after_splice_with_head", forged_relink(), [head(262)], S.FAIL, "and the held head for 262 no longer matches"),
    ("writer_full_rewrite_no_head", full_rewrite(), [], S.CANNOT,
     "writer removes, renumbers and recomputes everything: internally perfect -- only CANNOT_ESTABLISH is honest"),
    ("writer_full_rewrite_with_held_head", full_rewrite(), [head(262)], S.FAIL,
     "the same rewrite against a head for 262 someone kept: the log now ends at 261"),
    ("writer_full_rewrite_with_held_head_261", full_rewrite(), [head(261)], S.FAIL,
     "or a held head for 261: same entry number, different head (equivocation)"),
]

bad = 0
for vid, ents, heads, want, why in V:
    got, reasons = S.check(ents, heads)
    ok = got == want
    bad += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {vid:40s} {got:17s} expect {want:17s} | {why}")
    if not ok:
        print("       ", reasons)
print(f"{len(V) - bad}/{len(V)} vectors give their expected result")
sys.exit(1 if bad else 0)
