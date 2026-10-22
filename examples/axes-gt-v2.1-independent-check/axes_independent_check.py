"""Independent check of the AXES Golden Trace gt-v2.1 corpus (tag corpus/2026-10-12-gt-v2.1), written from the published text
(docs/09, docs/09a, VERIFY.md, the bundle README) with invinoveritas's own RFC 8785 implementation (services/work_acceptance.jcs,
the canonicaliser our signed work-acceptance records use, inlined below). No AXES code is imported or run.
Scope of that canonicaliser, checked rather than assumed: it is RFC 8785 for objects, arrays, strings, integers, booleans and null with
key order by code point. That equals JCS when there are no floats and every key is ASCII; the script asserts both on every hashed value
(AXES pins 0 JSON floats in hash scope) and stops if either fails.
  envelope_hash      = sha256(JCS(envelope minus integrity.envelope_hash and integrity.envelope_signature)), bare lowercase hex.
                       docs/09a s4 lists recorded_at as excluded (recipient_stamped); this script reports BOTH readings.
  chain              = each envelope's integrity.previous_envelope_hash equals the previous envelope_hash; genesis = 64 zeros
  chain_head         = the last envelope_hash
  files              = sha256(file bytes) equals manifest.files[path]
  bundle hash        = which reading of the manifest reproduces bundle_manifest_hash (reported, not assumed)"""
import hashlib, json, os, sys


def _scope_ok(v):
    if isinstance(v, float):
        raise SystemExit("float in hash scope: outside this canonicaliser's checked scope")
    if isinstance(v, dict):
        for k, x in v.items():
            if not k.isascii():
                raise SystemExit(f"non-ASCII key {k!r}: code-point order may differ from JCS UTF-16 order")
            _scope_ok(x)
    elif isinstance(v, list):
        for x in v:
            _scope_ok(x)


def jcs(v):
    """services/work_acceptance.jcs (invinoveritas), inlined; valid JCS within the scope _scope_ok enforces."""
    _scope_ok(v)
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
H = lambda b: hashlib.sha256(b).hexdigest()
def check(root, bundle):
    d = os.path.join(root, "examples", bundle, "out"); m = json.load(open(os.path.join(d, "manifest.json")))
    envs = [json.loads(l) for l in open(os.path.join(d, "envelopes.jsonl"), "rb").read().decode("utf-8").splitlines() if l.strip()]
    ok_hash = ok_link = ok_09a = 0; prev = "0" * 64
    for e in envs:
        x = json.loads(json.dumps(e)); i = x.get("integrity", {}); i.pop("envelope_hash", None); i.pop("envelope_signature", None)
        h = H(jcs(x)); ok_hash += h == e["integrity"]["envelope_hash"]
        y = json.loads(json.dumps(x)); y.pop("recorded_at", None); ok_09a += H(jcs(y)) == e["integrity"]["envelope_hash"]   # docs/09a section 4 reading
        ok_link += e["integrity"]["previous_envelope_hash"] == prev; prev = e["integrity"]["envelope_hash"]
    files_ok = sum(H(open(os.path.join(d, p), "rb").read()) == v for p, v in m["files"].items())
    cands = {"sha256(JCS(files))": H(jcs(m["files"])),
             "sha256(JCS(manifest minus bundle_manifest_hash))": H(jcs({k: v for k, v in m.items() if k != "bundle_manifest_hash"})),
             "sha256(sorted 'path  digest' lines)": H("".join(f"{v}  {p}\n" for p, v in sorted(m["files"].items())).encode())}
    hit = [k for k, v in cands.items() if v == m["bundle_manifest_hash"]]
    print(f"{bundle}: envelopes {len(envs)}; envelope_hash recomputed {ok_hash}/{len(envs)} (recorded_at IN the hash; with recorded_at excluded per docs/09a s4: {ok_09a}/{len(envs)}); previous links {ok_link}/{len(envs)}; "
          f"chain_head {'MATCHES' if prev == m['chain_head'] else 'DIFFERS'} {prev}; files {files_ok}/{len(m['files'])}; "
          f"bundle_manifest_hash {m['bundle_manifest_hash'][:16]}... reproduced by: {hit or 'NONE of ' + str(list(cands))}")
    return prev, m["bundle_manifest_hash"], hit
if __name__ == "__main__":
    root = sys.argv[1]
    for b in ("golden-trace", "golden-trace-ind"): check(root, b)
