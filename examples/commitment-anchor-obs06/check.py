"""commitment_anchor checker for the OBS-06 draft (stdlib only).

For each vector: (1) recompute the record's digest under the declared digest_rule and require it to equal
commitment_anchor.digest; (2) decide whether precedence is established under the declared anchor_time_rule:
  header_time_plus_tolerance  anchor_time + anchor_time_tolerance_s strictly before outcome_time (the default when absent);
  later_median                anchor_ceiling_time (median time of the 11 blocks after the anchor) strictly before outcome_time;
  height                      anchor_height strictly below outcome_height (outcome ordered by the same chain; no clock);
a rule whose inputs are missing, or an unknown rule, establishes nothing (no commitment_anchor, an unknown digest_rule or a
digest that does not recompute is ANCHOR_DOES_NOT_COVER_RECORD); (3) check the record's own claim: it may assert precedence only if established,
and if not established it must list "precedence_before_outcome" in does_not_assert.

What this does NOT check: that the proof really commits the digest at anchor_time, or that anchor_ceiling_time /
the heights are what the chain says (fetch the headers and recompute). Run the mechanism's own
verifier for that (for the OpenTimestamps vectors: `ots verify -d <digest> 38.ots`, then compare the block time).
Usage: python3 check.py [vectors.json]
"""
import hashlib, json, sys

NIP01_ESCAPES = {"\n": "\\n", "\"": "\\\"", "\\": "\\\\", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}

def nip01_str(s):
    # NIP-01: only these seven are escaped; every other character (other C0 controls, non-ASCII) is written as itself.
    return '"' + "".join(NIP01_ESCAPES.get(c, c) for c in s) + '"'

def nip01_json(x):
    if isinstance(x, str):
        return nip01_str(x)
    if isinstance(x, bool) or x is None:
        raise ValueError("not a NIP-01 event field")
    if isinstance(x, int):
        return str(x)
    if isinstance(x, list):
        return "[" + ",".join(nip01_json(i) for i in x) + "]"
    raise ValueError("not a NIP-01 event field")

def digest_of(record):
    """Recompute under digest_rule. None = the verifier cannot recompute (no anchor, unknown rule, malformed event)."""
    a = record.get("commitment_anchor")
    if not isinstance(a, dict) or a.get("digest_rule") != "nip01-event-id":
        return None
    e = record["subject"]
    try:
        ser = nip01_json([0, e["pubkey"], e["created_at"], e["kind"], e["tags"], e["content"]])
    except (KeyError, ValueError):
        return None
    return hashlib.sha256(ser.encode("utf-8")).hexdigest()

def ceiling_before_outcome(a, record):
    rule = a.get("anchor_time_rule", "header_time_plus_tolerance")
    try:
        if rule == "header_time_plus_tolerance":
            return a["anchor_time"] + a["anchor_time_tolerance_s"] < record["outcome_time"]
        if rule == "later_median":
            return a["anchor_ceiling_time"] < record["outcome_time"]
        if rule == "height":
            return a["anchor_height"] < record["outcome_height"]
    except KeyError:
        return False
    return False

def evaluate(record):
    a = record.get("commitment_anchor")
    d = digest_of(record)
    if d is None or d != a.get("digest"):
        return {"result": "ANCHOR_DOES_NOT_COVER_RECORD", "precedence_established": False}
    established = ceiling_before_outcome(a, record)
    asserts = record.get("asserts_precedence", False)
    declared = "precedence_before_outcome" in record.get("does_not_assert", [])
    if asserts and not established:
        res = "NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM"
    elif not established and not declared:
        res = "NONCONFORMING_UNDECLARED_LIMITATION"
    else:
        res = "CONFORMING"
    return {"result": res, "precedence_established": established}

def main(path):
    vectors = json.load(open(path))["vectors"]
    ok = 0
    for v in vectors:
        got = evaluate(v["record"])
        good = got == v["expect"]
        ok += good
        print(f"{'ok  ' if good else 'FAIL'} {v['id']:<40} {got['result']:<44} established={got['precedence_established']}")
    print(f"{ok}/{len(vectors)} agree")
    return 0 if ok == len(vectors) else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
