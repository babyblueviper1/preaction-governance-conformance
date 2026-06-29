# Per-entry recompute recipe — "this ledger entry re-derives to sound"

The recompute-kit leg for a **single `/ledger` entry**: given the raw signed Nostr event a public
relay served (plus the entry's ledger metadata), re-derive whether the entry is **sound** —
entirely from the bytes. No network, no `pip install`, nothing trusted but code you can read and
the published key you pin yourself.

This is the **first leg** of the per-entry "ledger entry re-derives to sound" composite, and the
**unit the [ERC-8275](https://api.babyblueviper.com/ledger) reputation axis aggregates**: reputation
is *recomputable, not stored*, precisely because every entry independently re-derives to sound from
public bytes. Outcome settlement is a separate, later leg (see "What this is / isn't").

## What "sound" means (each recomputed here)

| Check | What it proves |
|---|---|
| **id_integrity** | `nostr_event_id(event) == event.id == ledger.event_id` — the event bytes are internally consistent and *are* the id the ledger claims. |
| **signature_valid** | BIP-340 schnorr over the recomputed id verifies against `event.pubkey`, **and** `event.pubkey == the published verifier key`. invinoveritas issued it, untampered — checkable without trusting us. |
| **content_binding** | The content is self-consistent and bound. Two schemas, both handled: a **verdict proof** binds `{artifact_hash, verdict, verifier_pubkey}` (self-describing, verifier == signer == published); a **ledger record** commits to its record via `record_sha256 == sha256(json compact, sorted keys)`, recomputed from the record. |
| **commitment_anchor** | `commitment_proof.ots_anchor.digest == the recomputed event id` — the Bitcoin-PoW OpenTimestamps anchor stamps *this* id (the committed-before-outcome leg). Full `ots verify` is the online/binary step; this recipe checks the digest binds to the recomputed id. |

An entry is **sound** iff all four hold.

## Run it

```bash
python recompute_entry.py            # human-readable; exit 0 iff all sound AND tamper rejected
python recompute_entry.py --json     # machine-readable
```

```
[SOUND ] entry 36  (ledger_record)  id=da2dcd88c456fc02…
[SOUND ] entry 37  (ledger_record)  id=05da2881e85ba9cc…
[SOUND ] entry 38  (verdict_proof)  id=a42205d7e39c684f…
negative control (tampered entry must be rejected): ok — rejected
=> PASS  (3/3 sound, tamper rejected)
```

**Green-by-assertion is impossible:** the recipe recomputes each verdict from the bytes *and*
includes a negative control — it tampers one byte of an entry's content and **requires** the result
to flip to unsound (the id stops recomputing, so signature, binding, and anchor all fail). It exits
non-zero unless every real entry is sound **and** the tampered one is rejected.

## The vectors (`vectors/`)

Three **real** captured `/ledger` entries — the raw signed events as public relays served them, not
synthesised:

- **entry 38** — `verdict_proof.v1` (`approve_with_concerns`); also the first **forward-precedence:true**
  OTS anchor (Bitcoin block 955810). The schema the verification handshake passes agent-to-agent.
- **entry 37, 36** — `ledger record` posts (the `{record, record_sha256}` shape), showing the recipe
  handles both content kinds the live ledger emits.

Capture is reproducible from the live ledger via the sibling
[`../python/recompute_ledger.py`](../python/recompute_ledger.py) (the *online* whole-ledger companion,
which fetches every entry from relays). These vectors freeze three of them so the recipe runs offline
and byte-stable.

## Zero-dependency, by construction

`invinoveritas_verify.py` here is **byte-identical** to the audited pure-stdlib crypto in the
published [`invinoveritas-verify`](https://pypi.org/project/invinoveritas-verify/) package
(`diff` it against `../python/invinoveritas_verify.py`). The recipe imports only that + stdlib
(`hashlib`, `json`, `glob`, `copy`). No network calls — grep it.

## What this is / isn't

- **Is:** the per-entry soundness leg — *the entry exists, is internally consistent, was signed by the
  published key, binds to its content, and was anchored* — all recomputed from public bytes.
- **Isn't (separate legs):** the **outcome-settlement** leg (did the predicted outcome settle the way
  the verdict implied — the on-chain result, later in time), and the **full OTS `ots verify`** (this
  recipe confirms the digest binds to the recomputed id; running the calendar proof to a Bitcoin block
  is the binary step). The 8275 reputation axis reads the *aggregate* of sound, settled entries; this
  recipe is the per-entry input to that aggregate.

## Related

- [`../python/recompute_ledger.py`](../python/recompute_ledger.py) — online, whole-ledger (fetches from relays)
- [`../python/invinoveritas_verify.py`](../python/invinoveritas_verify.py) — the audited single-proof verifier (source of the vendored crypto)
- [preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance) — the conformance suite (independent verdict + external Bitcoin-anchored ordering, same recompute-from-bytes discipline)
