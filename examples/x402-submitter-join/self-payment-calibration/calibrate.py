#!/usr/bin/env python3
"""Second labelled payee for the x402#2887 self-payment rules (stdlib only, offline).

Inputs (pinned in inputs/, hashes in SHA256SUMS):
  payee_0x161d_usdc_transfers.json        our payee's 300 most recent USDC token transfers (Blockscout, Base)
  flagged_0x4fabc1df_token_transfers.json  token transfers of the one wallet PAYEE_FUNDED flagged that we don't own
  stillmarcus24/x402-submitter-join@3e4c955 market_join.json (not vendored: that repo has no licence; fetched once by
    commit and checked against MARKET_JOIN_SHA256, then cached in inputs/), the population out-degree is read from
  ../labels.csv                            our ground truth: every payer in the window, from our own keys + revenue ledger

It scores two rules against the labels:
  PAYEE_FUNDED   payer received a token transfer from the payee (stillmarcus24's second rule)
  OUT-DEGREE     CONFIRMED_EXTERNAL iff degree >= T, else UNCLASSIFIED (never counted external)
and checks the one precondition both rules share: that a counted "settlement" or "funding edge" is canonical USDC.
"""
import csv, hashlib, json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PAYEE = "0x161dbdd73d025e9aedd4918a67c28e5bf9a87fb9"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
PLAIN_TRANSFER = "0xa9059cbb"   # same exclusion as ../submitter_join.py: a plain transfer is not a facilitator settlement
THRESHOLDS = [2, 3, 5, 10]
MARKET_JOIN_URL = "https://raw.githubusercontent.com/stillmarcus24/x402-submitter-join/3e4c955/market_join.json"
MARKET_JOIN_SHA256 = "d37f601135739d7345ece47a5d19fcb45635e52fbf7c99debf5b2b9fc6266a4a"
MARKET_JOIN_CACHE = "stillmarcus24_market_join_3e4c955.json"


def market_join():
    path = os.path.join(HERE, "inputs", MARKET_JOIN_CACHE)
    if not os.path.exists(path):
        data = urllib.request.urlopen(MARKET_JOIN_URL, timeout=60).read()
        open(path, "wb").write(data)
    data = open(path, "rb").read()
    got = hashlib.sha256(data).hexdigest()
    if got != MARKET_JOIN_SHA256:
        sys.exit(f"market_join.json sha256 {got} != pinned {MARKET_JOIN_SHA256}")
    return json.loads(data)


def load(name):
    return json.load(open(os.path.join(HERE, "inputs", name)))


def main():
    labels = {r["address"]: r["label"] for r in csv.DictReader(open(os.path.join(HERE, "labels.csv")))}
    t = load("payee_0x161d_usdc_transfers.json")
    inbound = [x for x in t if x["to"] == PAYEE][:50]          # the window stillmarcus24 sampled
    settlements = [x for x in inbound if x["token"].lower() == USDC and x["method"] != PLAIN_TRANSFER]
    not_settlements = [x for x in inbound if x not in settlements]

    # PAYEE_FUNDED, naive (any token) vs canonical-USDC-only funding edges
    flagged = load("flagged_0x4fabc1df_token_transfers.json")
    out_edges = [(x["to"], x["token"].lower()) for x in t + flagged if x["from"] == PAYEE and x["to"] != PAYEE]
    funded_any = {a for a, _ in out_edges}
    funded_usdc = {a for a, tok in out_edges if tok == USDC}

    def score(funded, rows):
        tp = sum(1 for x in rows if x["from"] in funded and labels.get(x["from"]) == "self")
        fp = sum(1 for x in rows if x["from"] in funded and labels.get(x["from"]) != "self")
        fn = sum(1 for x in rows if x["from"] not in funded and labels.get(x["from"]) == "self")
        return dict(flagged=tp + fp, true_pos=tp, false_pos=fp, missed_self=fn)

    # out-degree over stillmarcus24's population
    m = market_join()
    p2p = {}
    for r in m["results"]:
        if r.get("error") or not r.get("submitters"):
            continue
        for p in r.get("payers") or []:
            p2p.setdefault(p.lower(), set()).add(r["payee"].lower())
    degree = {k: len(v) for k, v in p2p.items()}

    deg_rows = []
    for T in THRESHOLDS:
        ce = [x for x in settlements if degree.get(x["from"], 0) >= T]
        wrong = [x for x in ce if labels.get(x["from"]) != "external"]
        ext = sum(1 for x in settlements if labels.get(x["from"]) == "external")
        deg_rows.append(dict(threshold=T, confirmed_external=len(ce), self_confirmed_external=len(wrong),
                             external_left_unclassified=ext - (len(ce) - len(wrong)),
                             self_left_unclassified=sum(1 for x in settlements if labels.get(x["from"]) == "self")))

    by_label = {}
    for x in settlements:
        by_label[labels.get(x["from"], "unlabelled")] = by_label.get(labels.get(x["from"], "unlabelled"), 0) + 1
    out = dict(
        window=dict(first=inbound[-1]["ts"], last=inbound[0]["ts"], inbound_transfers=len(inbound),
                    settlements=len(settlements), not_settlements=[dict(tx=x["tx"], frm=x["from"], value=x["value"],
                    method=x["method"]) for x in not_settlements]),
        labels_over_settlements=by_label,
        payee_funded_any_token=score(funded_any, inbound),
        payee_funded_canonical_usdc=score(funded_usdc, settlements),
        spoofed_funding_edges=sorted({f"{a} via token {tok}" for a, tok in out_edges if tok != USDC}),
        self_degrees=sorted({degree.get(x["from"], 0) for x in settlements if labels.get(x["from"]) == "self"}),
        out_degree=deg_rows,
    )
    json.dump(out, open(os.path.join(HERE, "results.json"), "w"), indent=2)
    print(json.dumps(out, indent=2))
    # assertions this file pins
    assert out["payee_funded_any_token"]["false_pos"] == 2, "spoofed edge must reproduce as the naive rule's false positive"
    assert out["payee_funded_canonical_usdc"]["false_pos"] == 0
    assert all(r["self_confirmed_external"] == 0 for r in deg_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
