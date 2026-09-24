#!/usr/bin/env python3
"""Issue an evidence_set over LIVE content from a public ledger, then resolve it offline three ways.

Sources are real retrievals at run time: content-addressed records served by api.babyblueviper.com/record/<sha256>
(the URL names the sha256 of the bytes it serves, so snippet_sha256 must equal the id in the URL -- an independent
cross-check the draft does not need but we get for free) plus one retrieval that returns no content (404) and is
recorded unpinned with no_content_returned, as the possession rule requires.

    python3 examples/evidence-set-cold/run_live_ledger.py [out_dir]
"""
import datetime, hashlib, json, os, shutil, sys, urllib.error, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import evidence_set_check as E

BASE = "https://api.babyblueviper.com/record/"
IDS = ["064bb61b158ec8d863e04bb3eb040fe494c5be9d3088414408d691fb13505da3",
       "aba24be0b26463773432d1d090a16601440ba09a0ea8b81ab9fbe1051634e476",
       "3eb0a7b1e386990dd692c5c7c7ad71ce8ff3a973f225ae8cc4dcac7c48fc9d28"]
MISSING = BASE + "0" * 64


def now():
    t = datetime.datetime.now(datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "evidence-set-cold/1"}), timeout=30) as r:
            return r.read()
    except urllib.error.HTTPError:
        return None


def main(out):
    os.makedirs(os.path.join(out, "content"), exist_ok=True)
    entries = []
    for i in IDS + [None]:
        url = BASE + i if i else MISSING
        ts, body = now(), get(url)
        if body:
            d = hashlib.sha256(body).hexdigest()
            assert d == i, f"server served bytes whose sha256 is not the id in the URL: {url}"
            open(os.path.join(out, "content", d), "wb").write(body)
            entries.append({"url": url, "snippet_sha256": d, "retrieved_at": ts, "pinned": True, "content_kind": "full_resource"})
        else:
            entries.append({"url": url, "snippet_sha256": None, "retrieved_at": ts, "pinned": False, "unpinned_reason": "no_content_returned"})
    payload = {"evidence_set": E.build(entries)}
    json.dump(payload, open(os.path.join(out, "payload.json"), "w"), indent=1)
    pinned_only = {"evidence_set": E.build([e for e in entries if e["pinned"]])}
    held = {"hashes": {hashlib.sha256(open(os.path.join(out, "content", f), "rb").read()).hexdigest() for f in os.listdir(os.path.join(out, "content"))}}
    r = {}
    r["partial (3 pinned + 1 no_content_returned), all content held"] = E.resolve(payload, held)
    r["fully pinned (the 3), all content held"] = E.resolve(pinned_only, held)
    r["fully pinned, content not held"] = E.resolve(pinned_only)
    tamper = dict(held, by_url={BASE + IDS[0]: hashlib.sha256(b"tampered").hexdigest()})
    tamper["hashes"] = held["hashes"] - {IDS[0]}
    r["fully pinned, one item's held bytes differ"] = E.resolve(pinned_only, tamper)
    lines = []
    for k, (tok, rep) in r.items():
        lines.append(f"{k}: {tok}  items={[i['reason'] for i in rep.get('items', [])]}  root={rep.get('evidence_root')}")
    print("\n".join(lines))
    json.dump({k: v[1] for k, v in r.items()}, open(os.path.join(out, "resolutions.json"), "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_run"))
