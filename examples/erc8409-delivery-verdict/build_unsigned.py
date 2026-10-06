"""Rebuilds the unsigned vectors (quote, request, delivery records) -> vectors_unsigned.json. The signed proofs in vectors.json come from
POST /review sign=true on each case's deliveryRecordJcs."""
import json, hashlib
from eth_utils import keccak
import q8409 as Q

def jcs(o):          # RFC 8785 for this data (ASCII strings, integers, no floats): sorted keys, no whitespace
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

SCHEME = "org.invinoveritas.example.http-json/1"       # EXAMPLE scheme: canonical request bytes = JCS({method, url, body})
request = {"method": "POST", "url": "https://api.example.com/v1/forecast", "body": {"city": "Santiago", "days": 7}}
req_bytes = jcs(request)
quote = {"issuer": "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", "payer": "0x2222222222222222222222222222222222222222",
         "recipient": "0x3333333333333333333333333333333333333333", "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
         "amount": "1000000", "requestScheme": SCHEME, "requestHash": "0x" + keccak(req_bytes).hex(),
         "quoteId": "0x" + "bb" * 32, "validAfter": "1788372000", "validUntil": "1788372300"}
env = {"chainId": "8453", "quote": quote, "signature": Q.sign(8453, quote, "0x" + "00" * 31 + "01")}
qd = Q.quote_digest(8453, quote)

def record(body_obj, status=200):
    body = jcs(body_obj)
    return {"scheme": "invinoveritas.delivery-record/1",
            "quote": {"chainId": "8453", "quoteDigest": qd, "quoteId": quote["quoteId"], "issuer": quote["issuer"],
                      "requestScheme": SCHEME, "requestHash": quote["requestHash"]},
            "request": request,
            "response": {"status": status, "contentType": "application/json", "body": body.decode(),
                         "bodySha256": hashlib.sha256(body).hexdigest()},
            "question": "Does this response deliver what the quoted request asked for?"}

days = [{"date": f"2028-09-0{i+3}", "tmin_c": 6 + i, "tmax_c": 18 + i} for i in range(7)]
cases = {"delivered": record({"city": "Santiago", "days": 7, "forecast": days}),
         "paid_not_delivered": record({"city": "Santiago", "days": 7, "forecast": []})}
out = {"envelope": env, "quoteDigest": qd, "canonicalRequest": req_bytes.decode(), "cases": {}}
for k, r in cases.items():
    a = jcs(r)
    out["cases"][k] = {"deliveryRecord": r, "deliveryRecordJcs": a.decode(), "deliveryRecordSha256": hashlib.sha256(a).hexdigest()}
json.dump(out, open("vectors_unsigned.json", "w"), indent=1)
print("quoteDigest", qd, "requestHash", quote["requestHash"])
for k, v in out["cases"].items(): print(k, v["deliveryRecordSha256"], len(v["deliveryRecordJcs"]))
