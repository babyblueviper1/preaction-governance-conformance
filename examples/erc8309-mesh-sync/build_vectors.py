#!/usr/bin/env python3
"""Builds vectors.json for check_mesh_sync.py. Counts in C1/C4 are Echo's enumerated numbers (damon:receiptos 2026-10-05/06):
origin ENSBoiler 419 (agent-attestations) / 413 (agent-attestations:wyriwe); NAS 0.7.0 held 299/413 in :wyriwe; Railway holds the 413
plus 1312 locally-originated records (1725). Record ids are synthetic; only the set relations are real."""
import json

def ids(prefix, n, start=0): return [f"{prefix}:{i:05d}" for i in range(start, start + n)]

def paged(recs, size=500, tag="p"):
    pages, toks = {}, [f"{tag}{i}" for i in range(max(1, (len(recs) + size - 1) // size))]
    for i, t in enumerate(toks):
        pages[t] = {"records": recs[i * size:(i + 1) * size], "cursor": toks[i + 1] if i + 1 < len(toks) else None}
    pages["start"] = toks[0]
    return pages

A, B = "agent-attestations", "agent-attestations:wyriwe"
oA, oB = ids("ensboiler:A", 419), ids("ensboiler:B", 413)
local = ids("railway:local", 1312)
V = []
V.append({"id": "E1-cursor-chain-to-end", "kind": "enumerate", "rule": "R1", "pages": paged(oB + local),
          "expected": {"enumerated": "COMPLETE", "count": 1725, "single_page_read": "INCOMPLETE"}})
p2 = paged(oB + local); p2["note"] = "requested limit=5000; the node silently serves 500 and a cursor"
V.append({"id": "E2-silent-clamp-is-a-sample", "kind": "enumerate", "rule": "R1", "pages": p2,
          "expected": {"single_page_read": "INCOMPLETE", "count": 1725}})
p3 = {"start": "c0", "c0": {"records": ids("x", 3), "cursor": "c1"}, "c1": {"records": ids("x", 3, 3), "cursor": "c0"}}
V.append({"id": "E3-cursor-cycle-fails-closed", "kind": "enumerate", "rule": "R1", "pages": p3, "expected": {"enumerated": "ERROR"}})
V.append({"id": "C1-converged-per-origin-totals-differ", "kind": "convergence", "rule": "R2",
          "origins": {"ensboiler": {A: oA, B: oB}},
          "nodes": {"nas-0.8.0": {A: paged(oA), B: paged(oB)}, "railway": {A: paged(oA), B: paged(oB + local)}, "ensboiler": {A: paged(oA), B: paged(oB)}},
          "expected": {"per_origin": "CONVERGED", "totals_equal": False}})
x_hold = oA[:-2] + ids("x:local", 2)
V.append({"id": "C2-equal-totals-still-missing", "kind": "convergence", "rule": "R2",
          "origins": {"ensboiler": {A: oA}},
          "nodes": {"node-x": {A: paged(x_hold)}, "ensboiler": {A: paged(oA)}},
          "expected": {"per_origin": "NOT_CONVERGED", "totals_equal": True,
                       "detail": {"ensboiler/" + A: {"MISSING": {"node-x": 2}}}}})
V.append({"id": "C3-declared-namespace-hidden-from-default-view", "kind": "convergence", "rule": "R2",
          "origins": {"ensboiler": {A: oA, B: oB}},
          "nodes": {"node-y": {A: paged(oA)}, "ensboiler": {A: paged(oA), B: paged(oB)}},
          "expected": {"per_origin": "NOT_CONVERGED", "detail": {"ensboiler/" + A: "CONVERGED", "ensboiler/" + B: {"MISSING": {"node-y": "namespace_absent"}}}}})
V.append({"id": "C4-pre-upgrade-nas-0.7.0", "kind": "convergence", "rule": "R2",
          "origins": {"ensboiler": {B: oB}},
          "nodes": {"nas-0.7.0": {B: paged(oB[:299])}, "ensboiler": {B: paged(oB)}},
          "expected": {"per_origin": "NOT_CONVERGED", "detail": {"ensboiler/" + B: {"MISSING": {"nas-0.7.0": 114}}}}})
V.append({"id": "N1-nodeType-outside-envelope", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab", "signer": "0xcd"}, "served_fields": {"nodeId": "0xab", "signer": "0xcd", "nodeType": "Router"},
          "acted_on": ["nodeId", "nodeType"], "expected": {"result": "NONCONFORMANT:unsigned_behaviour_field:nodeType"}})
V.append({"id": "N2-nodeType-inside-envelope", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab", "signer": "0xcd", "nodeType": "Router"}, "served_fields": {"nodeId": "0xab", "signer": "0xcd", "nodeType": "Router"},
          "acted_on": ["nodeId", "nodeType"], "expected": {"result": "CONFORMANT"}})
V.append({"id": "N3-served-role-differs-from-signed", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab", "nodeType": "Router"}, "served_fields": {"nodeId": "0xab", "nodeType": "Origin"},
          "acted_on": ["nodeType"], "expected": {"result": "MISMATCH:nodeType"}})
V.append({"id": "N4-non-behavioural-field-may-sit-outside-if-declared-inert", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab", "nodeType": "Origin"}, "served_fields": {"nodeId": "0xab", "nodeType": "Origin", "displayName": "ENSBoiler"},
          "acted_on": ["nodeId", "nodeType"], "inert": ["displayName"], "expected": {"result": "CONFORMANT"}})
# N5 is Pavlo's counterexample (topic 16, 2026-10-06): the adapter simply leaves nodeType out of
# acted_on. Under R3 as originally written this passed, while the implementation still acted on an
# unsigned nodeType — the exact case R3 exists to catch, defeated one level up by the declaration.
V.append({"id": "N5-undeclared-unsigned-field-is-not-a-pass", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab"}, "served_fields": {"nodeId": "0xab", "nodeType": "Router"},
          "acted_on": ["nodeId"], "expected": {"result": "NONCONFORMANT:undeclared_served_field:nodeType"}})
# N6 is the residual gap, kept visible on purpose: declaring nodeType inert conforms, because no
# check over declared sets can refute the assertion. The omission has become an accountable claim;
# its truthfulness is a code-binding/provenance obligation, not a conformance one.
V.append({"id": "N6-inert-assertion-conforms-and-is-the-residual-gap", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab"}, "served_fields": {"nodeId": "0xab", "nodeType": "Router"},
          "acted_on": ["nodeId"], "inert": ["nodeType"], "expected": {"result": "CONFORMANT"}})
V.append({"id": "N7-field-cannot-be-both-acted-on-and-inert", "kind": "envelope", "rule": "R3",
          "signed_fields": {"nodeId": "0xab", "nodeType": "Router"}, "served_fields": {"nodeId": "0xab", "nodeType": "Router"},
          "acted_on": ["nodeId", "nodeType"], "inert": ["nodeType"],
          "expected": {"result": "NONCONFORMANT:contradictory_declaration:nodeType"}})
json.dump({"schema": "erc8309-mesh-sync-vectors-v0", "rules": ["R1 ENUMERATE", "R2 PER-ORIGIN", "R3 ENVELOPE"], "vectors": V},
          open("vectors.json", "w"), indent=1, sort_keys=True)
print("wrote", len(V), "vectors")
