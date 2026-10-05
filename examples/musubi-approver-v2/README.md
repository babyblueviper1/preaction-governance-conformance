# MUSUBI third-party approver (a2a-approval-v2): fields + vectors for settle v1.10

This is the approver path for MUSUBI conditional actions, built at Toshikatsu Oga's request
([horizon-shield#29](https://github.com/ogasurfproject-jpg/horizon-shield/issues/29)). Today's settle counts an approval as soon as an entry
with the right `action` string is present (`contract_v0.py` L641-655 and v1-v1.9, per Oga). This file set pins who may approve and verifies it
offline. Settle stays a pure recompute.

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
