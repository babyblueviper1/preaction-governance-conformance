#!/usr/bin/env python3
"""Submitter-keyed coverage of the 105-contract x402 facilitator registry (a second implementation of the
question in x402-foundation/x402#2887, correcting the payee-keyed join).

For every payee disclosed in RayR-audit's probe_results_v3.csv (A_out rows), on Base:
  1. list the payee's most recent inbound USDC transfers (Blockscout v2, first page, <= 50);
  2. keep facilitator-style settlements: the transfer was NOT a plain transfer() by the payer
     (method != 0xa9059cbb), e.g. transferWithAuthorization 0xe3ee160e / receiveWithAuthorization 0xef55bec6
     or a settlement contract call;
  3. for up to SAMPLE of them, fetch the transaction: tx.from (submitter) and tx.to (called contract);
  4. a settlement is COVERED when tx.from or tx.to is one of the registry's 105 addresses.

Output (resumable): results.jsonl, one row per payee. Summary: python3 submitter_join.py --summary
Usage: python3 submitter_join.py <probe_results_v3.csv> <base_facilitators.csv> [--rate 0.35]
No keys. Base only (a payee with no Base USDC inflow is reported as such, not as uncovered).
"""
import csv, json, os, sys, time, urllib.request

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
PLAIN_TRANSFER = "0xa9059cbb"
SAMPLE = 5
BS = "https://base.blockscout.com/api/v2"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.jsonl")  # resumable


def get(url, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "x402-submitter-join/1 (research)", "accept": "application/json"})
            return json.load(urllib.request.urlopen(req, timeout=30))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(2 * (i + 1))
        except Exception:
            time.sleep(2 * (i + 1))
    return "ERR"


def summary():
    rows = [json.loads(l) for l in open(OUT)]
    base = [r for r in rows if r["status"] == "ok"]
    with_settle = [r for r in base if r["settlements_sampled"]]
    cov_any = [r for r in with_settle if r["covered"] > 0]
    cov_all = [r for r in with_settle if r["covered"] == r["settlements_sampled"]]
    tot_s = sum(r["settlements_sampled"] for r in with_settle)
    tot_c = sum(r["covered"] for r in with_settle)
    subs = {}
    for r in with_settle:
        for s in r["samples"]:
            k = s["registry_match"] or "UNREGISTERED"
            subs[k] = subs.get(k, 0) + 1
    print(json.dumps(dict(
        payees=len(rows), fetch_errors=len(rows) - len(base),
        payees_no_base_usdc_inflow=sum(1 for r in base if r["inbound_usdc"] == 0),
        payees_inflow_but_no_facilitator_style=sum(1 for r in base if r["inbound_usdc"] and not r["settlements_sampled"]),
        payees_with_facilitator_settlements=len(with_settle),
        payees_any_settlement_covered=len(cov_any), payees_all_sampled_covered=len(cov_all),
        settlements_sampled=tot_s, settlements_covered=tot_c,
        settlement_coverage=round(tot_c / tot_s, 3) if tot_s else None,
        by_registry_facilitator=dict(sorted(subs.items(), key=lambda kv: -kv[1])),
    ), indent=1))


def main(probe, registry, rate):
    reg = {r["address"].lower(): r["facilitator"] for r in csv.DictReader(open(registry))}
    payees = []
    for r in csv.DictReader(open(probe)):
        if r["gap_type"] == "A_out":
            for p in r["payees"].split(";"):
                if p and p.lower() not in [x.lower() for x in payees]:
                    payees.append(p)
    done = set()
    if os.path.exists(OUT):
        done = {json.loads(l)["payee"].lower() for l in open(OUT)}
    print(f"{len(payees)} distinct payees, {len(done)} done", flush=True)
    with open(OUT, "a") as f:
        for i, p in enumerate(payees):
            if p.lower() in done:
                continue
            d = get(f"{BS}/addresses/{p}/token-transfers?type=ERC-20&filter=to&token={USDC}")
            time.sleep(rate)
            if d == "ERR":
                row = dict(payee=p, status="fetch_error")
            else:
                items = (d or {}).get("items", [])
                fac = [x for x in items if (x.get("method") or "") != PLAIN_TRANSFER]
                samples = []
                for x in fac[:SAMPLE]:
                    tx = get(f"{BS}/transactions/{x['transaction_hash']}")
                    time.sleep(rate)
                    if not isinstance(tx, dict):
                        continue
                    frm = (tx.get("from") or {}).get("hash", "").lower()
                    to = (tx.get("to") or {}).get("hash", "").lower()
                    payer = ((x.get("from") or {}).get("hash") or "").lower()
                    if frm == payer:
                        continue          # the payer submitted it itself: not a facilitator settlement
                    samples.append(dict(tx=x["transaction_hash"], method=x.get("method"), submitter=frm, called=to,
                                        registry_match=reg.get(frm) or reg.get(to)))
                row = dict(payee=p, status="ok", inbound_usdc=len(items), settlements_sampled=len(samples),
                           covered=sum(1 for s in samples if s["registry_match"]), samples=samples)
            f.write(json.dumps(row) + "\n"); f.flush()
            if i % 25 == 0:
                print(f"{i}/{len(payees)} {p[:10]} {row.get('status')} inbound={row.get('inbound_usdc')} "
                      f"settle={row.get('settlements_sampled')} cov={row.get('covered')}", flush=True)


if __name__ == "__main__":
    if "--summary" in sys.argv:
        summary()
    else:
        rate = float(sys.argv[sys.argv.index("--rate") + 1]) if "--rate" in sys.argv else 0.35
        main(sys.argv[1], sys.argv[2], rate)
