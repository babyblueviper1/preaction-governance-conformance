# A verdict record that re-derives an independent work-acceptance record

This example states an evidence format and a rule so that a verdict record of
[draft-wright-verdict-record](https://datatracker.ietf.org/doc/draft-wright-verdict-record/) can cite an independent
work-acceptance record as its evidence. A checker of the draft can then verify the record and re-derive its verdict
without trusting the record's issuer or the verdict record's writer.

The evidence is a real record: receipt `e62b99634b1660262f3cb45ff6f07c9cc81aa63e6e8251682f4c4864fa7c5eb5`, issued
2026-11-17 for [holistis/agent-receipt-verify#103](https://github.com/holistis/agent-receipt-verify/issues/103). It judged a
mainnet x402 purchase against criteria committed before the payment, and the producer later co-signed it. holistis keeps
the same record as a vector in its own repository
(`vectors/acceptance-binding/real-record-producer-signed-live.json`).

## Format

Name: `https://github.com/babyblueviper1/preaction-governance-conformance/blob/main/examples/verdict-record-work-acceptance/README.md#format`

**The item.** An item is a JSON object with the members `receipt` and `signature`, as
`https://api.babyblueviper.com/work-acceptance/record/<receipt_sha256>` publishes them in its member `record`. The
`timestamp` member there is an annotation and is not part of the item. `record.json` here is that object in RFC 8785
(JCS) form.

**The trust anchor.** The checker holds a key document as its own input, named `invinoveritas-checker-keys`. That
document is published at `https://api.babyblueviper.com/.well-known/invinoveritas-checker-keys.json`. `checker-keys.json`
here holds its bytes as of 2026-11-17.

**When an item meets the format's rules.** All of the following must hold:

1. `receipt.schema` is `trilatic.acceptance-receipt/1.2`.
2. `signature.alg` is `Ed25519`, and `signature.key_id` equals `receipt.key_id`.
3. The held key document lists that `key_id` with `alg` `Ed25519` and `status` `active`.
4. `signature.value`, in base64, verifies under that key's `public_key_base64` over the RFC 8785 (JCS) bytes of `receipt`.
   The SHA-256 of those same bytes is the record's `receipt_sha256`.
5. `receipt.results` is a non-empty array of objects. Each object has a boolean `required` and a string `result`.
6. `receipt.verdict` equals the result of the rule below, applied to `receipt.results`.

**No upper time bound.** The format gives none. `receipt.issued_utc` is the checker's own signed statement, and the
RFC 3161 token over the receipt is published beside the item, not inside it. A verdict record that needs a time bound
on this evidence must get one some other way.

## Rule

Name: `https://github.com/babyblueviper1/preaction-governance-conformance/blob/main/examples/verdict-record-work-acceptance/README.md#rule`

**Input.** `check.inputs` has exactly one member, `results`, normally bound to the cited item at pointer
`/receipt/results`. The value is an array of objects, each with a boolean `required` and a string `result`. Any other
input, or a value of another shape, is a FAIL of step 3.

**Result.** Look only at the entries with `required` true:

- `"fail"` if any of them has the result `fail`;
- otherwise `"incomplete"` if any of them has the result `not-evaluated` or `error`;
- otherwise `"pass"`.

This is Trilatic's acceptance rule, as ruled on
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4) (2026-10-17).

## The cases

Each case uses the same policy, `policy.json`: format the one above, `citation_depth` 1. Each also uses the same upper
time bound, `2026-11-17T23:00:00.000000Z`.

| case | evidence | trust anchors | reference checker (-03) |
|---|---|---|---|
| `p1-pass` | `record.json` | `checker-keys.json` | released: PASS, PASS, PASS |
| `n1-stated-fail` | `record.json` | `checker-keys.json` | refused: step 3 FAILs (the rule gives `pass`, the record states `fail`) |
| `n2-tampered-item` | `record-tampered.json` (one result and the verdict changed after signing) | `checker-keys.json` | held: the item does not meet the format, so step 2 does not rely on it |
| `n3-key-not-held` | `record.json` | `checker-keys-empty.json` | held: no key for the record's `key_id` |

    python3 gen.py                                   # rewrites the verdict records and cases.json from record.json
    git clone https://github.com/diggertydog/verdict-record-test-vectors vr
    VRCHECK=vr python3 run.py                        # results.json; needs the Python package cryptography

`held_invinoveritas_work_acceptance.py` is the format and the rule above, written as a module of that checker's
`held/` directory.

## What this shows, and what it does not

A checker that holds the key document can confirm two things without asking us: the record is the one our key signed,
and the verdict it states is the one its own per-criterion results give.

It does not show that any single criterion was judged correctly. Each criterion's `finding` is the checker's statement
about the delivered bytes. The file digests and the criteria commitment in the receipt let a party re-judge them, but
the rule here does not.
