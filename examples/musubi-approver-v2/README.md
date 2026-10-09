# MUSUBI third-party approver (a2a-approval-v2): fields + vectors for settle v1.10

This is the approver path for MUSUBI conditional actions, built at Toshikatsu Oga's request
([horizon-shield#29](https://github.com/ogasurfproject-jpg/horizon-shield/issues/29)). In settle v0 to v1.3 (`contract_v0.py` L641-655), an approval counted as
soon as an entry with the right `action` string was present. From v1.4 an approval needs the principal's signature, and from v1.6 that signature
covers a2a-approval-v2 bytes naming the terms by `contract_sha256` (corrected per Oga, horizon-shield#29, 2026-10-05). Until v1.10 the only key
that could approve was a party's. This file set pins a third-party approver and verifies it offline. Settle v1.10
([53bece9f](https://github.com/ogasurfproject-jpg/horizon-shield/commit/53bece9f)) runs these nine vectors 9/9 and vendors `verify_approval_v2.py`. Settle stays a pure recompute.

## Contract side (both parties sign it)

```json
"grant": {
  "conditional": [{"action": "emit_witness", "requires": "approver"}],
  "approval_policy": {"allow_unscoped": false,
                      "approvers": [{"name": "invinoveritas", "public_key_ed25519_b64": "<32-byte std base64>", "actions": ["emit_witness"]}]}
}
```

## Approval (an entry in the execution record's `approvals[]`)

```json
{"action": "emit_witness", "by": "approver", "approver": "invinoveritas", "valid_until_height": 980000,
 "nonce": "<32 lowercase hex>", "single_use": true, "sig_b64": "<64-byte std base64>"}
```

The signature is Ed25519 by the pinned key over

    b"a2a-approval-v2\n" + canonical({"contract_sha256", "action", "approver_key", "valid_until_height", "nonce", "single_use"})

- `canonical()` and `contract_sha256()` are the ones in `musubi-v0/contract_v0.py`. `build_vectors.py` cross-checks the digest against that
  module (`HS_MUSUBI=<path>`).
- Binding the full contract digest, rather than `contract_id`, stops an approval from being replayed onto different terms, including a
  different approver policy.
- Time ordering (`valid_until_height` against the action's anchor height, and `single_use`) stays with settle's existing v1.1/v1.4 rules.

## Results (`verify_approval_v2.py`)

`approved`, or `approval_unverified` with a reason:

| Reason | Meaning |
|---|---|
| `not_an_approver_approval` | The entry is not an approver approval |
| `malformed` | A required field is missing or ill-typed |
| `approver_not_pinned` | The named approver is not in the contract's policy |
| `action_not_permitted_for_approver` | The pinned approver may not approve this action |
| `malformed_key_or_signature` | The pinned key or the signature is not valid base64 of the right length |
| `bad_signature` | The signature does not verify against the pinned key |

A contract that pins no approvers reads `approval_self_asserted`.

## Vectors

`vectors.json` holds 9 vectors (CC0) and runs 9/9 with `python3 verify_approval_v2.py`.

- **The pair:** `v2-valid-approval` (approved) and `v2-forged-unpinned-key` (same fields and name, signed by an unpinned key -> `bad_signature`).
- **Also covered:**
  - a genuine approval replayed onto a contract with other terms;
  - a field tampered after signing;
  - an action the approver may not approve;
  - an unpinned approver name;
  - today's bare action string;
  - a malformed nonce;
  - a contract with no approver pinned.

The keys are TEST keys from fixed seeds, so the file regenerates byte-identically. The base contract is
`base_second_contract_AB.json`, from horizon-shield @8546c8a (MIT, (c) The HORIZONs Co., Ltd.).

## Note for v1.10

`contract_v0.check_terms` currently accepts `approval_policy` only as `{allow_unscoped}`, so it must also accept `approvers[]`
(each entry: `name`, a canonical 32-byte `public_key_ed25519_b64` like `witnesses[]`, and a non-empty `actions[]`).

## Batch entrypoint (for a board-refereed run)

    python3 batch_approval_v2.py IN OUT

`IN` is a JSON array `[{"name", "contract", "approval" | null}, ...]`. `OUT` gets one answer per fixture,
`{"<name>": {"result", "reason"}}`, or `{"<name>": {"error"}}` for a fixture it could not evaluate. No expected value is read, so a
referee can hold the answers and compare them itself, the shape of the TSUNAGI batch contract. `approval: null` is answered with the
contract's policy reading. The logic is `verify_approval_v2.py` imported unchanged.

`python3 referee_selftest.py` runs it the way a referee would: the 9 fixtures without their `expect` fields go into one batch file,
the command runs as a subprocess, and every answer is compared with `expect` (9/9), plus a malformed fixture that must come back as
`{"error"}` without ending the batch.
