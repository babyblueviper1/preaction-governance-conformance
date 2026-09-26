# draft-krausz-verification-state §3.1 on invinoveritas /verify-proof

`check_live.py` (stdlib, no key) exercises the live endpoint against §3.1's states:

| Input | Expected | Why |
|---|---|---|
| a real signed proof (v22 demo event `6e1b4de0…`) | `verified` | all checks hold |
| the same proof with one content byte changed | `contradicted`, `valid: false` | a check failed: a finding about the event |
| an event missing NIP-01 fields | `contradicted` | the explicit input shape checks are findings |
| ledger entry #1 (`eb222944…`), early flat format whose signed bytes were not retained | `indeterminate` + `state_reason: absence` | the check ran and found no signal |

Run: `python3 check_live.py` (all four PASS as of 2026-09-26).

## The fourth state: `not_evaluated` + `instrument_failure`
An exception inside the verifier itself (an import or library failure, a bug in our code) must never be reported as a finding about
the event. It cannot be forced from outside, so it is covered by the server's unit tests. Only the dedicated input-error type raised by
the explicit NIP-01 checks counts as a finding; any other exception, including a plain `ValueError` from a library, returns
`valid: false` (fail closed) with `state: not_evaluated`, `state_reason: instrument_failure`. The server test, verbatim:

```python
def test_verifier_exception_is_instrument_failure_not_a_finding():
    # an unexpected exception inside OUR verifier (not a ValueError from input checks) must not read as a verdict
    with mock.patch("nostr.event.Event", side_effect=RuntimeError("library blew up")):
        r = ps.verify_proof_event(copy.deepcopy(EV))
    assert r["valid"] is False
    assert r["state"] == "not_evaluated" and r["state_reason"] == "instrument_failure"
    assert "not a finding about this event" in r["error"]
```

Response fields: `state` on every response; `state_reason` where §3.1 requires one (named `state_reason`, not `reason`, because
legacy responses already use `reason` as free text).
