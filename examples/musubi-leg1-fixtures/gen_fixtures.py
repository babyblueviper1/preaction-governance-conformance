#!/usr/bin/env python3
"""Leg-1 (record -> batch) regression vectors for NENRIN MUSUBI anchor composition (horizon-shield#25), CC0.
Every batch is derived byte-wise from the REAL stamped batch entry63.raw; the record is the real execution 19c44a79.
    python3 gen_fixtures.py                       # writes leg1_vectors.json (+ SHA256SUMS)
    python3 gen_fixtures.py --check <musubi-v0>   # runs every vector through that tree's anchor_compose.batch_ops + batch_leg_check
"""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
RAW = open(os.path.join(HERE, "entry63.raw"), "rb").read()
HX = "19c44a791a007f2a7f9038c455f70ab2d137083e9e06491136b8895d191e7a53"
T = RAW.decode("utf-8")
ENTRY_START = T.index('{"sha":"' + HX + '"') if '{"sha":"' + HX + '"' in T else T.index('"sha":"' + HX + '"') - 1


def entry_span():
    """[start, end) of the execution entry object inside records[] (balanced braces, strings respected)."""
    i = T.index('"sha":"' + HX + '"'); s = T.rindex("{", 0, i); depth = 0; j = s; instr = False; esc = False
    while True:
        c = T[j]
        if instr:
            esc = (c == "\\") and not esc
            if c == '"' and not esc: instr = False
        elif c == '"': instr = True
        elif c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: return s, j + 1
        j += 1


s, e = entry_span()
ENTRY = T[s:e]
rest = T[:s] + T[e:]
rest = rest.replace("[,", "[").replace(",,", ",").replace(",]", "]")        # remove the entry from records[] cleanly


def with_top(text, key, value_json):
    """Insert "key":value as the first member of the top-level object."""
    return "{" + json.dumps(key) + ":" + value_json + "," + text[1:]


V = [
    ("L1-control-real-entry63", RAW, "accepted", None,
     "The real stamped batch: the record is listed once in records[] with its own kind and schema."),
    ("L1-digest-only-under-rejected", with_top(rest.replace('"count":2', '"count":1'), "rejected", "[" + ENTRY + "]").encode(), "refused", "record_not_listed_in_batch",
     "The execution entry moved from records[] to a rejected[] list; count adjusted so only the listing rule decides."),
    ("L1-digest-only-under-supersedes", with_top(rest.replace('"count":2', '"count":1'), "supersedes", json.dumps({"sha": HX})).encode(), "refused", "record_not_listed_in_batch",
     "The digest appears only as supersedes.sha, never in records[]."),
    ("L1-not-json-log-line", ('2026-09-29T00:46:08Z intake accepted "sha":"%s" kind=execution\n' % HX).encode(), "refused", "batch_not_json",
     "A log line carrying the exact byte pattern: a raw byte search would accept it."),
    ("L1-listed-as-kind-agreement", T.replace(ENTRY, ENTRY.replace('"kind":"execution"', '"kind":"agreement"')).encode(), "refused", "record_kind_mismatch",
     "Listed in records[] once, but with kind agreement instead of execution."),
]


def write():
    out = {"schema": "musubi-leg1-fixtures-v1", "license": "CC0-1.0", "source": "babyblueviper1/preaction-governance-conformance examples/musubi-leg1-fixtures",
           "record_file": "exec_19c44a79.json", "record_sha256_of_file": hashlib.sha256(open(os.path.join(HERE, "exec_19c44a79.json"), "rb").read()).hexdigest(),
           "record_digest_hex": HX, "base_batch_file": "entry63.raw", "base_batch_sha256": hashlib.sha256(RAW).hexdigest(),
           "vectors": [{"id": i, "batch_hex": b.hex(), "batch_sha256": hashlib.sha256(b).hexdigest(), "expect": x, "reason": r, "note": n} for i, b, x, r, n in V]}
    p = os.path.join(HERE, "leg1_vectors.json"); json.dump(out, open(p, "w"), indent=1); open(p, "a").write("\n")
    with open(os.path.join(HERE, "SHA256SUMS"), "w") as f:
        for fn in ("entry63.raw", "exec_19c44a79.json", "leg1_vectors.json"):
            f.write(hashlib.sha256(open(os.path.join(HERE, fn), "rb").read()).hexdigest() + "  " + fn + "\n")
    print(f"wrote {len(V)} vectors")


def check(tree):
    sys.path.insert(0, tree)
    import anchor_compose as A
    import settle_v1_1 as v11
    rec = json.load(open(os.path.join(HERE, "exec_19c44a79.json")))
    d = v11.commitment_digest(rec); assert d.hex() == HX, d.hex()
    bad = 0
    for v in json.load(open(os.path.join(HERE, "leg1_vectors.json")))["vectors"]:
        b = bytes.fromhex(v["batch_hex"])
        try:
            A.batch_ops(d, b, rec); got, why = "accepted", None
        except A.Refused as e:
            got, why = "refused", e.code
        ok = (got, why) == (v["expect"], v["reason"]); bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {v['id']:34s} batch_ops -> {got}{' '+why if why else ''}")
    print(f"{len(V) - bad}/{len(V)} match"); return 1 if bad else 0


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(check(sys.argv[sys.argv.index("--check") + 1]))
    write()
