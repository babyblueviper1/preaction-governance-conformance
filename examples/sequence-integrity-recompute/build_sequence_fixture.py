#!/usr/bin/env python3
"""
build_sequence_fixture.py -- generates the sequence-integrity fixture set.

Included for transparency: this is how the committed fixtures were made.
The checker (check_sequence_integrity.py) never runs this; it verifies the
committed bytes. Requires `cryptography` (generator only -- the checker is
zero-dependency).

Construction follows verification.v0.4 rev-1 §3.3 exactly:
  leaf hash     = SHA256(0x00 || leaf_payload_bytes)
  interior node = SHA256(0x01 || left || right)
  odd node      = promoted unchanged (no self-pairing)
Inclusion proof = ordered leaf-to-root [{"sibling": hex, "position": "left"|"right"}]
"""
import base64, hashlib, json, os, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "agentoracle-receipt-spec", "examples", "v0.3-composed")
OUT = os.path.dirname(os.path.abspath(__file__))

# ---- JCS (same rules as the checker; fixture payloads are int/str only) ----
def jcs(o):
    if o is None: return "null"
    if o is True: return "true"
    if o is False: return "false"
    if isinstance(o, str):
        out=['"']
        esc={'"':'\\"','\\':'\\\\','\b':'\\b','\f':'\\f','\n':'\\n','\r':'\\r','\t':'\\t'}
        for ch in o:
            out.append(esc.get(ch, '\\u%04x'%ord(ch) if ord(ch)<0x20 else ch))
        out.append('"'); return "".join(out)
    if isinstance(o, int) and not isinstance(o, bool): return str(o)
    if isinstance(o, list): return "["+",".join(jcs(v) for v in o)+"]"
    if isinstance(o, dict):
        items=sorted(o.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{"+",".join(jcs(k)+":"+jcs(v) for k,v in items)+"}"
    raise TypeError(type(o))

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64u_d(s): return base64.urlsafe_b64decode(s + "="*(-len(s)%4))

def leaf_hash(payload_bytes): return hashlib.sha256(b"\x00"+payload_bytes).digest()
def node_hash(l, r): return hashlib.sha256(b"\x01"+l+r).digest()

def build_tree(leaves):
    """Returns (root, levels) where levels[0]=leaf hashes."""
    levels=[list(leaves)]
    cur=list(leaves)
    while len(cur)>1:
        nxt=[]
        for i in range(0,len(cur)-1,2):
            nxt.append(node_hash(cur[i],cur[i+1]))
        if len(cur)%2==1:
            nxt.append(cur[-1])          # odd promotion
        levels.append(nxt); cur=nxt
    return cur[0], levels

def inclusion_proof(levels, index):  # noqa: F811
    proof=[]; i=index
    for lvl in levels[:-1]:
        if i%2==0 and i+1 < len(lvl):
            proof.append({"sibling": lvl[i+1].hex(), "position": "right"})
        elif i%2==1:
            proof.append({"sibling": lvl[i-1].hex(), "position": "left"})
        # i%2==0 and no right sibling -> promoted: contribute nothing this level
        i//=2
    return proof

def main():
    vectors=json.load(open(os.path.join(SPEC,"vectors.json")))
    accepts=vectors["accept_vectors"]
    os.makedirs(os.path.join(OUT,"entries"), exist_ok=True)
    os.makedirs(os.path.join(OUT,"log"), exist_ok=True)

    base_ms=1753660800000  # 2026-07-28T00:00:00Z, fixed for determinism
    leaves=[]; leaf_payloads=[]
    for n,a in enumerate(accepts,1):
        env=json.load(open(os.path.join(SPEC,a["jws_file"])))
        json.dump(env, open(os.path.join(OUT,"entries",f"entry-{n:03d}.json"),"w"),
                  indent=1)
        payload_bytes=b64u_d(env["payload"])
        env_hash=hashlib.sha256(payload_bytes).hexdigest()
        prot=json.loads(b64u_d(env["signatures"][0]["protected"]))
        lp={"envelope_hash": f"sha256-{env_hash}",
            "issuer_kid": prot["kid"],
            "log_time_ms": base_ms + n*1000,
            "typ": prot.get("typ","application/vnd.verification.v0.3+composed+jws")}
        lp_bytes=jcs(lp).encode()
        leaf_payloads.append(lp)
        leaves.append(leaf_hash(lp_bytes))

    json.dump(leaf_payloads, open(os.path.join(OUT,"log","leaves.json"),"w"), indent=1)

    # fixture log key
    sk=Ed25519PrivateKey.generate()
    pk=sk.public_key()
    from cryptography.hazmat.primitives import serialization
    raw_pub=pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid="log-fixture-seq-2026-07"
    json.dump({"keys":[{"kty":"OKP","crv":"Ed25519","kid":kid,"x":b64u(raw_pub)}]},
              open(os.path.join(OUT,"log","jwks-log.json"),"w"), indent=1)

    def make_sth(size, t_ms):
        root,levels=build_tree(leaves[:size])
        sth_payload={"root_hash": root.hex(), "sth_time_ms": t_ms, "tree_size": size}
        pb=jcs(sth_payload).encode()
        sig=sk.sign(pb)
        return {"payload": sth_payload, "kid": kid,
                "signature": b64u(sig)}, levels

    sth1,_=make_sth(4, base_ms+10_000)
    sth2,levels2=make_sth(7, base_ms+20_000)
    json.dump(sth1, open(os.path.join(OUT,"log","sth-1.json"),"w"), indent=1)
    json.dump(sth2, open(os.path.join(OUT,"log","sth-2.json"),"w"), indent=1)

    proofs={str(i+1): inclusion_proof(levels2,i) for i in range(7)}
    json.dump(proofs, open(os.path.join(OUT,"log","inclusion-proofs.json"),"w"), indent=1)
    print("fixture built: 7 entries, STH_1(size 4), STH_2(size 7), proofs, log JWKS")

if __name__=="__main__":
    main()
