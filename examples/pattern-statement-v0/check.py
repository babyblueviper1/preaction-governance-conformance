#!/usr/bin/env python3
"""Check a pattern statement (SPEC.md) against daily record log files. Standard library only.
usage: python3 -I check.py STATEMENT.json LOGFILE.jsonl [LOGFILE.jsonl ...]   (or a vector: python3 -I check.py --vector V.json)"""
import datetime, hashlib, json, sys

SCHEMA_LOG = "invinoveritas.work-acceptance.record_log.v1"
EMPTY = hashlib.sha256(f"{SCHEMA_LOG}|empty".encode()).hexdigest()
DAY = 86400


def jcs(o):
    # The log holds only strings, integers and nested objects/lists of them; for these, sorted keys + no whitespace + UTF-8 is RFC 8785.
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def merkle(leaves):
    if not leaves:
        return EMPTY
    lv = list(leaves)
    while len(lv) > 1:
        lv = [hashlib.sha256((lv[i] + (lv[i + 1] if i + 1 < len(lv) else lv[i])).encode()).hexdigest() for i in range(0, len(lv), 2)]
    return lv[0]


def day0(d):
    return int(datetime.datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc).timestamp())


def parse(text):
    rows = [x for x in text.split("\n") if x]
    header = json.loads(rows[0])
    return header, rows[1:]


def compute(subject, frm, to, files):
    """files: {date: text}. Returns (statement_fields, problems)."""
    problems = []
    roots, parsed = {}, {}
    for d, text in sorted(files.items()):
        h, lines = parse(text)
        ents = [json.loads(x) for x in lines]
        ok = (h.get("schema") == SCHEMA_LOG and h.get("date") == d and h.get("cutoff") == day0(d) + DAY
              and h.get("merkle_root") == merkle([hashlib.sha256(x.encode()).hexdigest() for x in lines])
              and h.get("n_records") == sum(1 for e in ents if e.get("type") == "record")
              and h.get("n_enrollments") == sum(1 for e in ents if e.get("type") == "enrollment")
              and all(jcs(e).decode() == x for e, x in zip(ents, lines)))
        if not ok:
            problems.append(f"LOG_ROOT_MISMATCH {d}")
        roots[d] = hashlib.sha256(jcs(h)).hexdigest(); parsed[d] = (h, ents)
    for d in sorted(parsed):
        prev = (datetime.date.fromisoformat(d) - datetime.timedelta(days=1)).isoformat()
        if prev in parsed and parsed[d][0].get("prev_root") != roots[prev]:
            problems.append(f"LOG_CHAIN_BROKEN {d}")
    days = []
    x = datetime.date.fromisoformat(frm)
    while x <= datetime.date.fromisoformat(to):
        days.append(x.isoformat()); x += datetime.timedelta(days=1)
    last = parsed.get(to)
    enr = next((e for e in (last[1] if last else []) if e.get("type") == "enrollment" and e.get("key") == subject), None)
    enrolled_at = enr["enrolled_at"] if enr else None
    nm = [d for d in days if d not in parsed or (enrolled_at is None) or day0(d) + DAY <= enrolled_at]
    lo, hi = day0(frm), day0(to) + DAY
    recs = [e for e in (last[1] if last else []) if e.get("type") == "record" and e.get("producer_key") == subject and lo <= e.get("created_at", -1) < hi]
    verdict, sig = {}, {"present": 0, "absent": 0, "declined": 0}
    for e in recs:
        verdict[e["verdict"]] = verdict.get(e["verdict"], 0) + 1
        sig[e["producer_signature"]] = sig.get(e["producer_signature"], 0) + 1
    rated = sig["present"] + sig["declined"]
    fields = {"log": {"first_root": roots.get(frm), "last_root": roots.get(to)},
              "measured": "NOT_MEASURED" if (enr is None or len(nm) == len(days)) else "measured",
              "not_measured_days": nm, "enrolled_at": enrolled_at,
              "counts": {"records": len(recs), "verdict": verdict, "producer_signature": sig},
              "decline_rate": (round(sig["declined"] / rated, 6) if rated else None)}
    return fields, problems


def check(statement, files):
    if statement.get("schema") != "invinoveritas.work-acceptance.pattern_statement.v0":
        return {"result": "INVALID", "problems": ["SCHEMA"]}
    p = statement.get("period") or {}
    fields, problems = compute(statement.get("subject_key"), p.get("from"), p.get("to"), files)
    if (statement.get("log") or {}) != fields["log"]:
        problems.append("LOG_REFERENCE_MISMATCH")
    for k in ("measured", "not_measured_days", "enrolled_at", "counts", "decline_rate"):
        if statement.get(k) != fields[k]:
            problems.append(f"STATEMENT_MISMATCH {k}")
    return {"result": "CONSISTENT" if not problems else "INCONSISTENT", "problems": problems, "recomputed": fields}


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--vector"]:
        bad = 0
        for f in a[1:]:
            v = json.load(open(f, encoding="utf-8"))
            got = check(v["statement"], v["log_files"])
            ok = got["result"] == v["expected"]["result"] and sorted(got["problems"]) == sorted(v["expected"]["problems"])
            print(("AGREE " if ok else "DIFF  ") + f.split("/")[-1] + ("" if ok else f"  got {got['result']} {got['problems']}"))
            bad += not ok
        print(f"{len(a) - 1 - bad}/{len(a) - 1} agree"); sys.exit(1 if bad else 0)
    st = json.load(open(a[0], encoding="utf-8"))
    files = {}
    for f in a[1:]:
        t = open(f, encoding="utf-8").read(); files[json.loads(t.split("\n", 1)[0])["date"]] = t
    out = check(st, files); print(json.dumps(out, indent=1)); sys.exit(0 if out["result"] == "CONSISTENT" else 1)
