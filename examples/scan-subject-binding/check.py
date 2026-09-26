#!/usr/bin/env python3
"""Cold checker for vectors.json. Imports nothing from build.py: recomputes every root, signature,
inclusion proof and answer from the vector bytes, then runs two verifiers side by side.

  result_only_check   what a verifier that reads only poisoning_scan.result concludes
                      (the shape of Agent Manifest v0.2 s3.2.5 / _verify.py at @0a2513df)
  subject_bound_check NO_FINDING only if the scan names a subject_digest that is the consumed
                      effective dataset, or is the corpus root and every consumed leaf has an
                      inclusion proof to it; otherwise CANNOT_ESTABLISH. NO_FINDING never means
                      POISONING_ABSENT.
Exit 0 iff every case matches its "expect".
"""
import hashlib, json, re, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def H(b): return hashlib.sha256(b).digest()
def leaf(d): return H(b"\x00" + d["id"].encode() + b"\x00" + d["content"].encode())
def mth(ls):
    if len(ls) == 1: return ls[0]
    k = 1
    while k * 2 < len(ls): k *= 2
    return H(b"\x01" + mth(ls[:k]) + mth(ls[k:]))
def root(docs): return "sha256:" + mth(sorted(leaf(d) for d in docs)).hex()
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def verify_inclusion(lf, index, size, path, want_root):
    # RFC 9162 s2.1.3.2
    if index >= size: return False
    fn, sn, r = index, size - 1, lf
    for p in path:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = H(b"\x01" + p + r)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0: fn >>= 1; sn >>= 1
        else:
            r = H(b"\x01" + r + p)
        fn >>= 1; sn >>= 1
    return sn == 0 and "sha256:" + r.hex() == want_root

def retrieve(docs, q, k=1):
    qt = set(q.lower().split())
    return sorted(docs, key=lambda d: (len(qt & set(d["content"].lower().replace(",", "").replace(".", "").split())), d["id"]), reverse=True)[:k]
def answer(ret): return re.search(r"is (\d+) USD", ret[0]["content"]).group(1) + " USD"

V = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
PK = Ed25519PublicKey.from_public_bytes(bytes.fromhex(V["test_public_key_ed25519"]))
def sig_ok(m):
    try: PK.verify(bytes.fromhex(m["sig"]), b"scan-subject-binding-v0\n" + canon(m["body"])); return True
    except Exception: return False

def check_decision(corpus, man, dec):
    """Bindings a replay verifier already checks: signature, root, recompute. Returns list of failures."""
    f = []
    if not sig_ok(man): f.append("signature")
    if man["body"]["rag_corpus"]["merkle_root"] != root(corpus): f.append("manifest root != corpus")
    if dec["corpus_root"] != root(corpus): f.append("decision corpus_root != corpus")
    ret = retrieve(corpus, dec["query"])
    if ret != dec["retrieved"]: f.append("retrieval recompute")
    if dec["effective_dataset_digest"] != root(dec["retrieved"]): f.append("effective digest")
    if answer(ret) != dec["answer"]: f.append("answer recompute")
    return f

def result_only(man): return "VALID" if man["body"]["rag_corpus"]["poisoning_scan"]["result"] == "clean" else "NOT_VALID"
def subject_bound(corpus, man, dec):
    s = man["body"]["rag_corpus"]["poisoning_scan"]
    if s.get("result") != "clean": return "NOT_VALID"
    subj = s.get("subject_digest")
    if subj is None: return "CANNOT_ESTABLISH"
    if subj == dec["effective_dataset_digest"]: return "NO_FINDING"
    if subj == root(corpus) == dec["corpus_root"]:
        cons = {leaf(d).hex() for d in dec["retrieved"]}
        proved = {p["leaf"] for p in dec["inclusion_proofs"]
                  if verify_inclusion(bytes.fromhex(p["leaf"]), p["index"], p["tree_size"], [bytes.fromhex(x) for x in p["path"]], subj)}
        return "NO_FINDING" if cons and cons <= proved else "CANNOT_ESTABLISH"
    return "CANNOT_ESTABLISH"

bad = 0
for name, c in sorted(V["cases"].items()):
    e = c["expect"]
    if name.startswith("c0"):
        fa = check_decision(c["corpus_A"], c["manifest_A"], c["decision_A"]); fb = check_decision(c["corpus_B"], c["manifest_B"], c["decision_B"])
        got = {"signatures": "valid" if not fa and not fb else "FAIL %s %s" % (fa, fb), "answer_A": c["decision_A"]["answer"], "answer_B": c["decision_B"]["answer"]}
        ok = all(got[k] == e[k] for k in got)
    else:
        f = check_decision(c["corpus"], c["manifest"], c["decision"])
        got = {"replay_bindings": "valid" if not f else "FAIL %s" % f, "result_only_check": result_only(c["manifest"]),
               "subject_bound_check": subject_bound(c["corpus"], c["manifest"], c["decision"])}
        ok = not f and all(got[k] == e[k] for k in ("result_only_check", "subject_bound_check") if k in e)
    bad += not ok
    print(("PASS " if ok else "FAIL ") + name, json.dumps(got))
print("%d/%d cases match" % (len(V["cases"]) - bad, len(V["cases"])))
sys.exit(1 if bad else 0)
