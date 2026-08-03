#!/usr/bin/env python3
"""broadcast_byte_diff.py — audit that a published Nostr proof event's broadcast copy is
byte-identical to the event you intended to publish, not just reachable under the same id.

WHY THIS EXISTS, AND WHY IT'S SEPARATE FROM THE OFFLINE SUITE: a plain reachability check
(does relay X return SOME event matching this id?) only proves the mesh has *something*
answering to the id -- it does not prove that something is byte-identical to what you meant
to publish. A corrupted-transcription bug upstream of the hash, or a relay serving a
colliding/mismatched copy, would pass a pure reachability check silently. This tool refetches
the event BY ID from each relay and compares every NIP-01 field individually.

This is the one tool in this repository that is NOT offline and NOT zero-dependency -- it
opens real websocket connections to real relays and needs `pip install websockets`. Everything
else here (verifier.py, run_conformance.py, examples/) recomputes from local bytes alone and
is deliberately kept that way; this tool audits a DIFFERENT property (did the network actually
receive what you sent), which structurally requires talking to the network. Keep it out of
run_conformance.py / CI for that reason -- it is a standalone audit utility, not a fixture check.

Usage:
    python3 tools/broadcast_byte_diff.py event.json
    python3 tools/broadcast_byte_diff.py event.json --relay wss://relay.example.org

event.json is a NIP-01 event object: {id, pubkey, created_at, kind, tags, content, sig}.

Real finding from building this (2026-08-01, everest-an/AwareLiquid/ERC-8337 exchange,
ethereum-magicians.org/t/25098): the first aggregation rule treated a relay CONNECTION ERROR
(transient, unrelated to data integrity) the same as an actual byte_mismatch -- found live
testing against relay.damus.io, which 503'd while nos.lol/relay.primal.net both confirmed
byte_identical on a real, already-published proof. A single flaky relay was masking an
otherwise fully-confirmed, clean result. Fixed: `all_byte_identical` requires >=1 relay
confirming identical AND zero relays reporting an actual mismatch -- a connection error or
not_found is inconclusive for that relay, not disqualifying.

SECOND finding (2026-08-03, everest-an/AwareLiquid/ERC-8350#20 -- same account this tool was
cited as ruling out that failure class): it didn't, for the RUN as a whole. `all_byte_identical`
is a plain bool, so when EVERY relay errors (network down, all URLs unreachable, whatever), the
result is `all_byte_identical: false` -- byte-for-byte identical to what a REAL, CONFIRMED
mismatch produces. Verified live: pointed the tool at two nonexistent relay hostnames, got
`{"relays": {"url1": "error: ...", "url2": "error: ..."}, "all_byte_identical": false}`, exit
code 1 -- same shape, same exit code a genuine byte_mismatch would produce. A caller reading
just the bool or the exit code cannot tell "we confirmed this doesn't match" from "we couldn't
reach anyone to check at all" -- the exact §6.1/§6.2 collapse this tool was cited as already
ruling out, just manifesting on the fail-safe side instead of the fail-unsafe side. Fixed:
`run_status` is now a required, explicit three-valued field (see verify_broadcast_bytes'
docstring) and the CLI exit code distinguishes all three cases numerically (0/1/2), not just
2 of them.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any

DEFAULT_RELAYS = ("wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net")

# The fields a relay's copy is compared against, field-by-field (not whole-object equality,
# since a relay MAY legally reorder JSON keys or add its own wrapper) -- what must be
# byte-identical is each of these NIP-01 values individually.
_COMPARE_FIELDS = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")


async def verify_broadcast_bytes(event: dict[str, Any], relays: tuple[str, ...] = DEFAULT_RELAYS) -> dict[str, Any]:
    """Byte-diff verification of a published proof event against each relay's own copy.

    Returns {relays: {url: 'byte_identical'|'byte_mismatch (field=X)'|'not_found'|'error: ...'},
             run_status: 'confirmed_match'|'confirmed_mismatch'|'inconclusive',
             all_byte_identical: bool, checked_at: int}. Never raises -- a single relay's
    failure doesn't fail the whole check; each relay gets its own independent status.

    run_status is the field that answers "did this run actually check anything," which
    all_byte_identical alone cannot: 'confirmed_mismatch' means at least one relay's copy
    provably differs; 'confirmed_match' means at least one relay confirmed identical and none
    disagreed; 'inconclusive' means NEITHER happened -- every relay errored/not_found, so
    nothing was actually verified. all_byte_identical is kept for backward compatibility (True
    only for confirmed_match) but must not be read alone -- False is the result for BOTH
    confirmed_mismatch and inconclusive, which is exactly the ambiguity run_status exists to
    remove. A caller that only checks the bool is back to the collapse this field fixes.
    """
    result: dict[str, Any] = {"relays": {}, "checked_at": int(time.time())}
    if not isinstance(event, dict) or not event.get("id"):
        result["error"] = "event must be an object with an id"
        result["run_status"] = "inconclusive"
        result["all_byte_identical"] = False
        return result
    try:
        import websockets
    except ImportError as exc:
        result["error"] = f"websockets not installed ({exc}) -- pip install websockets"
        result["run_status"] = "inconclusive"
        result["all_byte_identical"] = False
        return result

    event_id = event["id"]

    async def _check_one(url: str) -> str:
        try:
            sub_id = "bd1"
            req = json.dumps(["REQ", sub_id, {"ids": [event_id]}])
            async with websockets.connect(url, open_timeout=5) as ws:
                await ws.send(req)
                found: dict[str, Any] | None = None
                for _ in range(6):
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
                    if msg[0] == "EVENT" and msg[1] == sub_id:
                        found = msg[2]
                    elif msg[0] == "EOSE":
                        break
                if found is None:
                    return "not_found"
                for field in _COMPARE_FIELDS:
                    if found.get(field) != event.get(field):
                        return f"byte_mismatch (field={field})"
                return "byte_identical"
        except Exception as exc:  # noqa: BLE001
            return f"error: {exc}"

    for url in relays:
        result["relays"][url] = await _check_one(url)

    statuses = list(result["relays"].values())
    any_mismatch = any(v.startswith("byte_mismatch") for v in statuses)
    any_identical = any(v == "byte_identical" for v in statuses)
    if any_mismatch:
        result["run_status"] = "confirmed_mismatch"
    elif any_identical:
        result["run_status"] = "confirmed_match"
    else:
        result["run_status"] = "inconclusive"  # every relay errored or not_found -- nothing verified
    result["all_byte_identical"] = result["run_status"] == "confirmed_match"
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("event_file", help="path to a JSON file containing the NIP-01 event")
    ap.add_argument("--relay", action="append", dest="relays", default=None,
                     help="relay wss:// URL (repeatable); defaults to damus/nos.lol/primal")
    args = ap.parse_args()

    with open(args.event_file) as f:
        event = json.load(f)
        if "event" in event and "id" not in event:
            event = event["event"]  # tolerate a full /review sign=true response as input too

    relays = tuple(args.relays) if args.relays else DEFAULT_RELAYS
    result = asyncio.run(verify_broadcast_bytes(event, relays))
    print(json.dumps(result, indent=2))
    # Exit code is three-valued too, not just result.get("all_byte_identical") -- that collapsed
    # confirmed_mismatch and inconclusive onto the same nonzero code, which is the exact bug this
    # fix closes. 0 = confirmed_match, 1 = confirmed_mismatch (a real, checkable finding), 2 =
    # inconclusive (the run itself did not verify anything -- distinct from a real negative result).
    return {"confirmed_match": 0, "confirmed_mismatch": 1, "inconclusive": 2}[result["run_status"]]


if __name__ == "__main__":
    sys.exit(main())
