#!/usr/bin/env python3
"""ERC-8434 commitment-log worked example (data for garyyang-finchip/aid-standard examples/sepolia-commitment-log/).

Issuer: invinoveritas's dormant AID on Sepolia (0x4AA3...4991). It declares a commitment log in its own AID Document, issues a
`final` facet about the reference anchor B, then -- after B's subjectWindow.until has passed -- supersedes it in the log. Both log
heads are OpenTimestamps-anchored, so the reference resolver reports supersessionTiming not-before-outcome / reversedAfterOutcome.

    python3 build.py start        # T0: document, facet 1, entry 1 + head 1; OTS-stamp facet 1's digest and head 1 (pending)
    python3 build.py supersede    # after until: facet 2, entry 2 (supersedes entry 1) + head 2; OTS-stamp both (pending)
    python3 build.py upgrade      # complete pending .ots files once Bitcoin confirms
Writes state.json + the files it names. The signing key is read from the environment (SEPOLIA_ATTESTOR_KEY), never written.
"""
import base64, hashlib, json, os, sys, time
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

HERE = os.path.dirname(os.path.abspath(__file__))
ST = os.path.join(HERE, "state.json")
CHAIN = 11155111
ISSUER_ADDR = "0x4AA351E5f00eBe168E5C6f823f2940553d164991"
ISSUER = f"eip155:{CHAIN}:{ISSUER_ADDR}"
SUBJECT = f"eip155:{CHAIN}:0xd6b24DF77E6f5e7BEFf51460a1d60C2fb7ac9eb2"           # reference anchor B of the Sepolia worked example
FACET_TYPE = "aid:behavior/verification-verdict/v1"
RAW = "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/main/examples/aid-commitment-log/"
LOG_URI, DOC_URI = RAW + "log.json", RAW + "aid-document.json"
CALENDARS = ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org",
             "https://finney.calendar.eternitywall.com", "https://btc.calendar.catallaxy.com"]


def jcs(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def keccak(b):
    return "0x" + Web3.keccak(b).hex().removeprefix("0x")


def sha256hex(b):
    return "0x" + hashlib.sha256(b).hexdigest()


def log_tag(subject, facet_type, frm, until):
    """resolve.js logTag: keccak256(abi.encode(string subject, string facetType, uint64 from, uint64 until))."""
    return keccak(encode(["string", "string", "uint64", "uint64"], [subject, facet_type, frm, until]))


def head_of(tag, content, supersedes, prev):
    """head_n = keccak256(abi.encode(bytes32 tag, bytes32 content, bytes32 supersedes, bytes32 head_{n-1})); 0x00..00 = none."""
    b = lambda h: bytes.fromhex((h or "0x" + "00" * 32)[2:])
    return keccak(encode(["bytes32", "bytes32", "bytes32", "bytes32"], [b(tag), b(content), b(supersedes), b(prev)]))


def ots_stamp(digest_hex):
    """A detached SHA-256 .ots over the 32-byte digest itself (the reference verifier compares the stamped digest to it)."""
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.calendar import RemoteCalendar
    d = bytes.fromhex(digest_hex[2:])
    dtf = DetachedTimestampFile(OpSHA256(), Timestamp(d))
    ok = []
    for url in CALENDARS:
        try:
            dtf.timestamp.merge(RemoteCalendar(url).submit(d, timeout=15)); ok.append(url)
        except Exception as e:
            print("  calendar failed:", url, type(e).__name__)
    if len(ok) < 2:
        raise SystemExit("fewer than 2 calendars accepted the digest")
    ctx = BytesSerializationContext(); dtf.serialize(ctx)
    return base64.b64encode(ctx.getbytes()).decode(), ok


def sign_head(head):
    acct = Account.from_key(os.environ["SEPOLIA_ATTESTOR_KEY"])
    assert acct.address.lower() == ISSUER_ADDR.lower()
    return acct.sign_message(encode_defunct(hexstr=head)).signature.hex()


def write(name, obj):
    with open(os.path.join(HERE, name), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True); f.write("\n")


def start():
    if os.path.exists(ST):
        raise SystemExit("already started")
    t0 = int(time.time())
    doc = {"version": "aid-document/v1", "aid": ISSUER, "did": "did:aid:" + ISSUER, "updatedAt": t0, "facets": [],
           "commitmentLog": {"uri": LOG_URI, "hash": "keccak256", "headSigner": ISSUER_ADDR, "anchorKinds": ["ots"], "declaredAt": t0,
                             "witnesses": [{"kind": "ots", "endpoint": c} for c in CALENDARS[:2]]
                             + [{"kind": "git", "endpoint": "https://github.com/babyblueviper1/preaction-governance-conformance"}]}}
    win = {"from": t0 - 86400, "until": t0 + 8 * 3600}
    content1 = {"type": "invinoveritas.verification-verdict/v1", "subject": SUBJECT, "question": "is B's binding to ERC-8004 agent 11039 "
                "in force for its stated window?", "verdict": "in-force", "subjectWindow": win, "issuedAt": t0,
                "notice": "worked example for ERC-8434 section 7 commitment-log profile; not an assessment of any real agent"}
    d1 = sha256hex(jcs(content1))
    tag = log_tag(SUBJECT, FACET_TYPE, win["from"], win["until"])
    h1 = head_of(tag, d1, None, None)
    ots_f1, cal1 = ots_stamp(d1)
    ots_h1, calh1 = ots_stamp(h1)
    env1 = {"facetType": FACET_TYPE, "provenance": "ATTESTED", "issuer": ISSUER, "validUntil": t0 + 30 * 86400, "observedAt": t0,
            "subjectWindow": win, "finality": "final", "digest": d1, "access": {"mode": "PUBLIC"},
            "resolver": {"kind": "uri"}, "uri": RAW + "facet-1.json",
            "committedAt": {"anchor": "ots", "proof": {"ots": ots_f1}, "log": {"uri": LOG_URI, "position": 1}}}
    log = {"version": "invinoveritas.aid-commitment-log/v1", "issuer": ISSUER, "hash": "keccak256",
           "head_rule": "head_n = keccak256(abi.encode(bytes32 tag, bytes32 content, bytes32 supersedes, bytes32 head_{n-1})), zero = none",
           "tag_rule": "keccak256(abi.encode(string subject, string facetType, uint64 subjectWindow.from, uint64 subjectWindow.until))",
           "entries": [{"position": 1, "tag": tag, "content": d1, "supersedes": None, "head": h1, "prev": None,
                        "headSig": sign_head(h1), "anchor": {"kind": "ots", "ots": ots_h1, "status": "pending"}}]}
    write("aid-document.json", doc); write("facet-1.json", content1); write("envelope-1.json", env1); write("log.json", log)
    st = {"t0": t0, "until": win["until"], "docDigest": keccak(jcs(doc)), "d1": d1, "h1": h1, "cal": cal1 + calh1}
    write("state.json", st)
    print(json.dumps(st, indent=1))


if __name__ == "__main__":
    {"start": start}[sys.argv[1]]()
