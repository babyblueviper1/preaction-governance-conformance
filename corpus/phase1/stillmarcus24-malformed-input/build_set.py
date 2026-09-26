import json, tanilo_receipt_verify as t
VECTORS = {
 "env_not_object_string":      "not-an-envelope",
 "env_not_object_int":         12345,
 "env_null":                   None,
 "env_empty_object":           {},
 "signatures_string":          {"payload":"e30","signatures":"nope"},
 "signatures_int":             {"payload":"e30","signatures":7},
 "signatures_list_of_nondict": {"payload":"e30","signatures":["x",3]},
 "signatures_dict_not_list":   {"payload":"e30","signatures":{"a":1}},
 "payload_not_string_int":     {"payload":123,"signatures":[]},
 "payload_null":               {"payload":None,"signatures":[]},
 "payload_object":             {"payload":{"k":"v"},"signatures":[]},
 "missing_payload":            {"signatures":[]},
 "missing_signatures":         {"payload":"e30"},
 "signatures_empty_list":      {"payload":"e30","signatures":[]},
 "jws_not_object":             {"payload":"e30","jws":"str","signatures":[{"protected":"e30","signature":"x"}]},
}
# expected: the CONFORMANCE PROPERTY, in the draft vocabulary — a status, NEVER a raise.
# (draft-krausz-verification-state four-state vocab: valid|invalid|indeterminate|not_evaluated;
#  an exception is not one of the four, so a raise is a conformance FAILURE for any input.)
STATES = {"valid","invalid","indeterminate","not_evaluated"}
expected = {name: {"must_return_one_of": sorted(STATES), "must_not_raise": True,
                   "rationale": "malformed input is still input; a verifier that raises has opted out of the four-state vocabulary (draft §3.1)"}
            for name in VECTORS}
# RUN the reference implementation, record AS-RUN (never edited to match)
results = {}
for name, env in VECTORS.items():
    try:
        r = t.verify(env)
        results[name] = {"outcome":"returned","status":r.status,"indeterminate_reason":r.indeterminate_reason,"raised":False}
    except Exception as e:
        results[name] = {"outcome":"raised","exception":type(e).__name__+": "+str(e)[:80],"raised":True}
conforms = sum(1 for r in results.values() if not r["raised"])
json.dump(VECTORS, open("stillmarcus24-malformed-input/vectors.json","w"), indent=1)
json.dump(expected, open("stillmarcus24-malformed-input/expected.json","w"), indent=1)
json.dump({"implementation":"tanilo-receipt-verify==0.1.1","note":"as-run, not edited to match; failures would be reported",
           "conforming":conforms,"total":len(VECTORS),"results":results},
          open("stillmarcus24-malformed-input/results-tanilo-0.1.1.json","w"), indent=1)
print(f"packaged {len(VECTORS)} vectors | tanilo 0.1.1: {conforms}/{len(VECTORS)} return a status, {len(VECTORS)-conforms} raise")
