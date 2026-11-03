#!/usr/bin/env python3
"""Build the pattern-statement vectors from synthetic daily logs written to SPEC.md, with each expected statement worked out by
construction (the counts are what the builder put in), independently of check.py. Standard library only.
usage: python3 -I build_vectors.py  (writes vectors/*.json; re-running reproduces them byte for byte)"""
import copy, datetime, hashlib, json, os

SCHEMA_LOG = "invinoveritas.work-acceptance.record_log.v1"
EMPTY = hashlib.sha256(f"{SCHEMA_LOG}|empty".encode()).hexdigest()
K1 = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"     # the subject (synthetic)
K2 = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"     # another enrolled producer (synthetic)
D = ["2026-11-01", "2026-11-02", "2026-11-03"]


def jcs(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def t0(d):
    return int(datetime.datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc).timestamp())


def merkle(lv):
    if not lv:
        return EMPTY
    while len(lv) > 1:
        lv = [hashlib.sha256((lv[i] + (lv[i + 1] if i + 1 < len(lv) else lv[i])).encode()).hexdigest() for i in range(0, len(lv), 2)]
    return lv[0]


def rec(i, day, hour, verdict, key=K1):
    return {"type": "record", "receipt_sha256": hashlib.sha256(f"r{i}".encode()).hexdigest(), "created_at": t0(day) + hour * 3600,
            "criteria_id": "c" * 64, "verdict": verdict, "producer_key": key}


def state(r, cutoff, cosigned_at):
    if cosigned_at is not None and cosigned_at < min(cutoff, r["created_at"] + 72 * 3600):
        return "present"
    return "declined" if cutoff - r["created_at"] >= 72 * 3600 else "absent"


def build_days(enrolls, records, days=D, drop=(), prev0="0" * 64):
    """enrolls: [(key, enrolled_at)]; records: [(rec, cosigned_at|None)]. Returns {date: text}, {date: log_root}."""
    files, roots, prev = {}, {}, prev0
    for d in days:
        cut = t0(d) + 86400
        lines = [{"type": "enrollment", "key": k, "enrolled_at": at, "statement": f"invinoveritas work-acceptance enrollment v1 {k}",
                  "signature": "sig-" + k[-8:]} for k, at in enrolls if at < cut]
        for r, cs in records:
            if r["created_at"] < cut and any(k == r["producer_key"] and r["created_at"] >= at for k, at in enrolls):
                lines.append(dict(r, producer_signature=state(r, cut, cs)))
        lines.sort(key=lambda x: (x["type"], x.get("enrolled_at", x.get("created_at")), x.get("key", x.get("receipt_sha256"))))
        body = [jcs(x).decode() for x in lines]
        h = {"schema": SCHEMA_LOG, "date": d, "cutoff": cut, "prev_root": prev, "n_enrollments": sum(1 for x in lines if x["type"] == "enrollment"),
             "n_records": sum(1 for x in lines if x["type"] == "record"), "merkle_root": merkle([hashlib.sha256(b.encode()).hexdigest() for b in body]),
             "rules": "see SPEC.md"}
        root = hashlib.sha256(jcs(h)).hexdigest()
        if d not in drop:
            files[d] = "".join(x + "\n" for x in [jcs(h).decode()] + body); roots[d] = root
        prev = root
    return files, roots


def stmt(subject, frm, to, roots, measured, nm, enrolled_at, counts, rate):
    return {"schema": "invinoveritas.work-acceptance.pattern_statement.v0", "subject_key": subject, "period": {"from": frm, "to": to},
            "log": {"first_root": roots.get(frm), "last_root": roots.get(to)}, "measured": measured, "not_measured_days": nm,
            "enrolled_at": enrolled_at, "counts": counts, "decline_rate": rate}


def main():
    os.makedirs("vectors", exist_ok=True)
    EN = t0("2026-10-31") + 3600                              # K1 enrolled the day before the period
    R = [(rec(1, D[0], 2, "pass"), t0(D[0]) + 3 * 3600),        # co-signed in 1 h            -> present
         (rec(2, D[0], 5, "fail"), None),                       # never co-signed, > 72 h by? no: day3 cutoff - created = 67 h -> absent
         (rec(3, D[1], 1, "pass"), t0(D[1]) + 2 * 3600),        # present
         (rec(4, D[1], 9, "incomplete"), None),                 # absent at day3 cutoff (39 h)
         (rec(5, D[2], 4, "pass"), None),                       # absent
         (rec(6, D[0], 1, "pass", key=K2), None)]               # another producer: never counted for K1
    old = (rec(7, "2026-10-28", 1, "fail"), None)              # created 10-28 -> declined by 11-01 (> 72 h), but OUTSIDE the period
    files, roots = build_days([(K1, EN), (K2, EN)], R + [old])
    # by construction, period 11-01..11-03, as of the 11-03 cutoff: records 1-5 (K1, in period): pass 3, fail 1, incomplete 1;
    # states: 1 present, 2 absent (67 h), 3 present, 4 absent, 5 absent -> present 2, absent 3, declined 0 -> rate 0/2 = 0.0
    good_counts = {"records": 5, "verdict": {"pass": 3, "fail": 1, "incomplete": 1}, "producer_signature": {"present": 2, "absent": 3, "declined": 0}}
    vecs = {}
    vecs["01-consistent"] = (stmt(K1, D[0], D[2], roots, "measured", [], EN, good_counts, 0.0), files, "CONSISTENT", [])
    bad = copy.deepcopy(good_counts); bad["verdict"]["pass"] = 4; bad["records"] = 6
    vecs["02-counts-overstated"] = (stmt(K1, D[0], D[2], roots, "measured", [], EN, bad, 0.0), files, "INCONSISTENT", ["STATEMENT_MISMATCH counts"])
    # 03: day 2 rewritten with a wrong prev_root -> its own header is self-consistent, but it breaks the chain at day 2 and day 3
    f3 = dict(files); h, rest = f3[D[1]].split("\n", 1); hh = json.loads(h); hh["prev_root"] = "f" * 64
    f3[D[1]] = jcs(hh).decode() + "\n" + rest
    vecs["03-chain-broken"] = (stmt(K1, D[0], D[2], roots, "measured", [], EN, good_counts, 0.0), f3, "INCONSISTENT", ["LOG_CHAIN_BROKEN 2026-11-02", "LOG_CHAIN_BROKEN 2026-11-03"])
    # 04: record 3 (pass, present) deleted from the day-3 file, header left as it was
    f4 = dict(files); r3 = jcs(dict(R[2][0], producer_signature="present")).decode()
    f4[D[2]] = f4[D[2]].replace(r3 + "\n", "")
    vecs["04-line-removed"] = (stmt(K1, D[0], D[2], roots, "measured", [], EN, good_counts, 0.0), f4, "INCONSISTENT",
                               ["LOG_ROOT_MISMATCH 2026-11-03", "STATEMENT_MISMATCH counts"])
    # 05: a key that never enrolled -> honest NOT_MEASURED statement is consistent
    K3 = "did:key:z6MkfakeNeverEnrolledKey000000000000000000000000"
    zero = {"records": 0, "verdict": {}, "producer_signature": {"present": 0, "absent": 0, "declined": 0}}
    vecs["05-not-enrolled-honest"] = (stmt(K3, D[0], D[2], roots, "NOT_MEASURED", list(D), None, zero, None), files, "CONSISTENT", [])
    # 06: the same key claimed as measured with a clean bill -> refused
    vecs["06-not-enrolled-claimed-clean"] = (stmt(K3, D[0], D[2], roots, "measured", [], None, zero, None), files, "INCONSISTENT",
                                             ["STATEMENT_MISMATCH measured", "STATEMENT_MISMATCH not_measured_days"])
    # 07: day 2 has no file -> that day is not measured; counts still come from the day-3 (cumulative) file
    f7, r7 = build_days([(K1, EN), (K2, EN)], R + [old], drop=(D[1],))
    vecs["07-missing-day"] = (stmt(K1, D[0], D[2], r7, "measured", [D[1]], EN, good_counts, 0.0), f7, "CONSISTENT", [])
    # 08: enrolled during day 2 -> day 1 not measured; records before enrollment are not in the log at all (records 1, 2, 3 drop)
    EN2 = t0(D[1]) + 5 * 3600
    f8, r8 = build_days([(K1, EN2), (K2, EN)], R + [old])
    c8 = {"records": 2, "verdict": {"incomplete": 1, "pass": 1}, "producer_signature": {"present": 0, "absent": 2, "declined": 0}}
    vecs["08-enrolled-mid-period"] = (stmt(K1, D[0], D[2], r8, "measured", [D[0]], EN2, c8, None), f8, "CONSISTENT", [])
    # 09: a decline: record 2 checked a day later (period to 11-04), > 72 h, never co-signed -> declined; rate 1/3
    D4 = D + ["2026-11-04"]
    f9, r9 = build_days([(K1, EN), (K2, EN)], R + [old], days=D4)
    c9 = {"records": 5, "verdict": {"pass": 3, "fail": 1, "incomplete": 1}, "producer_signature": {"present": 2, "absent": 2, "declined": 1}}
    vecs["09-one-declined"] = (stmt(K1, D[0], D4[3], r9, "measured", [], EN, c9, round(1 / 3, 6)), f9, "CONSISTENT", [])
    for name, (st, fl, res, probs) in vecs.items():
        v = {"vector": name, "spec": "SPEC.md (pattern statement v0)", "statement": st, "log_files": fl,
             "expected": {"result": res, "problems": probs}}
        open(f"vectors/{name}.json", "w", encoding="utf-8").write(json.dumps(v, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(vecs)} vectors")


if __name__ == "__main__":
    main()
