#!/usr/bin/env python3
"""Black-box check of draft-krausz-verification-state §3.1 states on the LIVE invinoveritas /verify-proof (stdlib only).
Anyone can run it; it needs no key. Cases:
  1 a real signed proof (v22 mediator demo, event 6e1b4de0...)       -> state "verified", valid true
  2 the same proof with ONE content byte changed                      -> state "contradicted", valid false (a finding)
  3 a structurally malformed event (NIP-01 fields missing)            -> state "contradicted" (explicit input check = a finding)
  4 an early flat-format ledger entry whose signed bytes were not kept -> state "indeterminate", state_reason "absence"
The fourth §3.1 state, not_evaluated/instrument_failure (the verifier's OWN exception is never reported as a finding about the
event), cannot be forced from outside; it is covered by the server's unit tests (see README).
    python3 check_live.py [base_url]"""
import copy, json, sys, urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://api.babyblueviper.com").rstrip("/")
EVENT = json.load(open(__file__.rsplit("/", 1)[0] + "/../trace-v20-fixtures/events/v22_mediator_attestation_v2_keydoc_demo.json"))


def post(body):
    r = urllib.request.Request(BASE + "/verify-proof", data=json.dumps(body).encode(), headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=30))


tampered = copy.deepcopy(EVENT)
tampered["content"] = tampered["content"][:-2] + ("0" if tampered["content"][-2] != "0" else "1") + tampered["content"][-1]
cases = [
    ("real proof", {"event": EVENT}, lambda d: d.get("valid") is True and d.get("state") == "verified"),
    ("one byte changed", {"event": tampered}, lambda d: d.get("valid") is False and d.get("state") == "contradicted"),
    ("malformed event", {"event": {"id": "zz", "pubkey": 1}}, lambda d: d.get("state") == "contradicted"),
    ("ledger #1 (bytes not retained)", {"event_id": "eb22294404b2021588f90747b6404e878431191845c2aab26a919702394c68ac"}, lambda d: d.get("state") == "indeterminate" and d.get("state_reason") == "absence"),
]
fails = 0
for name, body, ok in cases:
    try:
        d = post(body)
        good = ok(d)
    except Exception as e:
        d, good = {"error": repr(e)}, False
    fails += not good
    print(f"{'PASS' if good else 'FAIL'}  {name:32s} valid={d.get('valid')} state={d.get('state')} state_reason={d.get('state_reason')}")
print("ALL PASS" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
