"""Run vectors.json against commitment.py. Exit 0 iff every vector matches. Offline (uses candidates_snapshot.json)."""
import hashlib
import json
import sys
from pathlib import Path

from commitment import Malformed, NotAttempted, commit, link

HERE = Path(__file__).parent
doc = json.loads((HERE / "vectors.json").read_text())
snap = json.loads((HERE / doc["candidates_snapshot"]).read_text())
CANDS = [c["nonce"] for c in snap["candidates"]]
ASSET, PAYER = snap["asset"], snap["authorizer"]


def _h(b):
    return "0x" + hashlib.sha256(b).hexdigest()


# What a receipt holder without the salt can compute from public data, per candidate nonce n.
LAZY_RULES = {
    "sha256(nonce)": lambda n: _h(bytes.fromhex(n[2:])),
    "salt=sha256(payer)": lambda n: commit("eip3009", ASSET, PAYER, n, _h(bytes.fromhex(PAYER[2:]))),
    "salt=zero": lambda n: commit("eip3009", ASSET, PAYER, n, "0x" + "00" * 32),
    "salt=nonce": lambda n: commit("eip3009", ASSET, PAYER, n, n),
    "salt=sha256(nonce)": lambda n: commit("eip3009", ASSET, PAYER, n, _h(bytes.fromhex(n[2:]))),
}


def attack(v):
    """Every lazy rule against every candidate (one indexed log query's worth): 5 x 12 = 60 hashes."""
    for n in CANDS:
        for rule in LAZY_RULES.values():
            if rule(n) == v["published"]:
                return {"recovered": n}
    return {"recovered": None}


fails = 0
for v in doc["vectors"]:
    try:
        if v["kind"] == "commit":
            got = {"commitment": commit(v["method"], v["asset"], v["authorizer"], v["nonce"], v["salt"])}
        elif v["kind"] == "link":
            got = link(v["commitment"], v["salt"], v["method"], v["asset"], v["authorizer"], CANDS)
        else:
            got = attack(v)
    except Malformed as e:
        got = {"malformed": e.condition}
    except NotAttempted as e:
        got = {"not_attempted": e.condition}
    ok = got == v["expect"]
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {v['id']}" + ("" if ok else f"  got={got} expect={v['expect']}"))
print(f"{len(doc['vectors']) - fails}/{len(doc['vectors'])} pass")
sys.exit(1 if fails else 0)
