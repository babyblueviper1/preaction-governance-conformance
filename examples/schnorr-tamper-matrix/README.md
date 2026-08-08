# Schnorr tamper matrix — is a NIP-01 checker actually checking, or a placebo?

Built jointly with [helmymekaoui-web](https://ethereum-magicians.org/t/29275) (ERC-8370,
Inheritable Agent Mandates). He built an independent BIP-340/NIP-01 verifier from scratch, self-
checked it against the 19 official BIP-340 test vectors (`bitcoin/bips`), then ran it cold against
two real `invinoveritas` `/ledger` verdicts — and, because "two OKs prove nothing if the checker
says yes to everything," tampered each verdict four ways to confirm his checker actually rejects
bad input. All four were caught.

This is that exact tamper matrix, reusable, run here against a third real verdict
(`mandate_gate_verdict.json` — invinoveritas `/ledger` entry 237, a real signed verdict with
`intended_verifier` bound to his own `MandateGate` contract, Base Sepolia
[`0x6882d039e266e5357d82cf3c7215b7639f5c24ea`](https://sepolia.basescan.org/address/0x6882d039e266e5357d82cf3c7215b7639f5c24ea)).

## The matrix

| Vector | What it tests | Must be caught by |
|---|---|---|
| content changed (e.g. `confidence`/`verdict`) | content is part of the signed preimage | `id_integrity` |
| `created_at` shifted 1 second | timestamp is part of the signed preimage | `id_integrity` |
| 1 bit flipped in the signature | the id stays correct (sig isn't in its own preimage) — the only vector that isolates whether schnorr verification is really running | `signature_valid` |
| pubkey swapped for another real key, id recomputed to match | forging a valid schnorr signature under a *different* key without its private half is computationally infeasible — id_integrity alone would pass here, so this is the vector that proves signature checking is load-bearing, not decorative | `signature_valid` |

A checker that accepts any row is a **constant-true placebo** — the same shape helmymekaoui-web
named directly: *"A 'golden vector reader' that reproduces values inline would pass every test
while proving nothing."*

## Run it

```bash
python3 check_tamper_matrix.py                       # bundled real verdict (ledger entry 237)
python3 check_tamper_matrix.py --file your_event.json # any NIP-01 event you have
```

Zero dependencies, offline. Crypto is `invinoveritas_verify.py`, the vendored pure-stdlib BIP-340
reference implementation — identical to the copy at the repo root; diff them if you don't trust
that claim.

## What this closes

That the verdict is **authentically `invinoveritas`'s**, byte-exact, untampered, and bound to the
declared `intended_verifier` — checkable by anyone re-running this file against the published
pubkey (`GET https://api.babyblueviper.com/.well-known/verifier-keys.json`), no API call, no trust
in either party.

## What this does NOT close (stated plainly, not hidden in a caveat)

Nothing about the **ECDSA/secp256k1 side** of a `MandateGate`-style on-chain gate. The two schemes
are genuinely different: schnorr (BIP-340) over `sha256(JSON[0,pubkey,created_at,kind,tags,content])`
(NIP-01) vs. ECDSA over a `keccak`/EIP-191 digest. Closing that gap is real, separate, **unbuilt**
work — either:

- an **off-chain adapter** that re-presents this event in the exact shape his gate already checks, or
- an **on-chain schnorr verifier** (the `ecrecover`-trick route, plus the x-only-key parity bit
  helmymekaoui-web flagged as still open).

This fixture doesn't paper over that gap by only testing the half that already works — it names the
boundary explicitly so the next person building the adapter knows exactly what's already proven and
what still needs proving.

## Provenance

Real exchange: [ethereum-magicians.org/t/29275, posts #17–22](https://ethereum-magicians.org/t/29275/22).
His independent verifier: `github.com/adn-ia/inheritable-agent-mandates/blob/main/conformance/verify_verdict.py`.
`mandate_gate_verdict.json` is `invinoveritas` `/ledger` entry 237 — reachable live at
`https://api.babyblueviper.com/ledger/237` and `https://api.babyblueviper.com/ledger/2d546ab9453484c6abab362cf50f787a19f288c226a70ff92bc4f8d384a92625`
(the same event_id lookup this exchange's other real gap led to).
