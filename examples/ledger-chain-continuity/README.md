# Chain continuity — closing the gap in issue #3 (non-equivocation)

**The gap, as filed (Rul1an, 2026-07-23):** every existing recipe in this suite verifies each
`/ledger` entry *independently*. `recompute_entry.py` re-derives id integrity, signature validity,
content binding, and the commitment anchor — all **per entry**. Nothing establishes a property of
the *sequence*: that the ledger one reader is served is the same ledger served to the next reader.
A host could hand auditor A a set that includes an entry and auditor B a set that omits it, and
**every entry either of them sees would still pass every per-entry check in this suite** — the
recompute cannot tell the two views apart. RFC 9943 (SCITT architecture) names this
**non-equivocation**, a separate requirement from append-only soundness.

## What invinoveritas's live `/ledger` already does about it

`/ledger` already hash-chains its entries (`services/ledger_chain.py`, built 2026-07-02 for a
*different* prior finding — MarkovianProtocol, microsoft/autogen#7353 — independently confirmed
live via `GET /ledger` on 2026-08-26: 248 entries total, 209 chained from entry #40 onward).
From entry #40 onward every entry carries:

```
chain = {
  prev_head_hash,               # the PRECEDING entry's head_hash
  content_hash,                 # sha256(canonical_json(record))
  head_hash,                    # sha256(content_hash + "|" + prev_head_hash)
}
```

The head is also independently broadcast to the same public Nostr relays the proof events go to
(`invinoveritas.ledger_chain_head.v1`) — so a third party who observes **two different heads for
the same entry number** on the shared relay set has caught a fork without trusting the API to
admit it. Entries #1–39 predate this and keep their original individual OTS anchors, unchanged
(retroactively chaining them would invalidate already-published signatures).

## What this recipe adds

`check_chain_continuity.py` recomputes the chain **offline, zero-dep**, from a captured entry
sequence:

1. `content_hash` re-derives from each entry's own `record`.
2. `head_hash` re-derives from `content_hash` + the entry's *own claimed* `prev_head_hash`.
3. **`prev_link`** — the entry's claimed `prev_head_hash` must equal the *preceding* entry's
   actual `head_hash`. This is the sequence-level check nothing else in this suite does.

```
$ python check_chain_continuity.py
  [OK  ] entry 245  content_hash=ok  prev_link=ok  head_hash=ok
  [OK  ] entry 246  content_hash=ok  prev_link=ok  head_hash=ok
  [OK  ] entry 247  content_hash=ok  prev_link=ok  head_hash=ok
  [OK  ] entry 248  content_hash=ok  prev_link=ok  head_hash=ok

  real sequence continuous: YES
  => PASS
```

**The negative control is the point of this example**, not an afterthought: it omits one real
entry from the middle of the sequence (simulating a server that hands this auditor a subset
skipping it) and shows that **every remaining entry is still individually sound** — `recompute_entry.py`'s
existing per-entry recipe would pass every one of them without complaint — but the *seam* right
after the omission fails `prev_link`, because the next entry's claimed `prev_head_hash` no longer
matches its new (wrong) predecessor. That is exactly the scenario the issue describes, reproduced
and caught.

```
  negative control -- omit entry 246 (every OTHER entry individually still sound):
    [OK  ] entry 245  prev_link=ok
    [FAIL] entry 247  prev_link=FAIL
    [OK  ] entry 248  prev_link=ok
  omission correctly caught by the seam's prev_link check: yes
```

## Honest scope — what this does NOT close

This recipe proves the sequence *you were handed* is internally continuous. It does **not**, by
itself, prove non-equivocation across two different observers who are each handed a different but
internally-continuous subset (or a different fork entirely) — an operator who fabricates two
complete, self-consistent forks and shows one to each auditor would pass this check on both forks
independently. Closing *that* needs one of the two legs the issue itself names:

- **Witness the sequence** — cross-check the recomputed `head_hash` against the independently
  broadcast Nostr event for the same entry number (a live network step, out of scope for this
  repo's offline/zero-dependency design — see the companion `../python/recompute_ledger.py` for
  the online whole-ledger check). Full closure per RFC 9943 / the C2SP tlog-witness pattern would
  need independent witness cosignatures over a consistency proof, which invinoveritas does not yet
  implement — real, disclosed future work, not built.
- **Keep the challenge portable** — already true structurally: a counter-verdict recomputes from
  its own bytes and does not need the ledger to admit it; it can be published anywhere and checked
  by anyone.

## The vectors (`vectors/`)

Four **real** consecutive `/ledger` entries (245–248), captured live from `GET
/ledger/{entry}` on 2026-08-26 — not synthesized. Each carries its full `record` and `chain`
block exactly as served.

## Zero-dependency, by construction

Pure stdlib (`hashlib`, `json`, `copy`, `glob`) — no `pip install`, no network call at runtime.
Diff `check_chain_continuity.py` against `services/ledger_chain.py` in the main invinoveritas repo
to confirm the recipe matches the live implementation's own math (both are short enough to read in
full).
