# reputation-pointer recompute — a real typed pointer, not a hypothetical schema

Closes a design commitment made and left open for nearly a month on
[a2aproject/A2A#1962](https://github.com/a2aproject/A2A/discussions/1962) ("Optional
verifiable-reputation pointer on the Agent Card").

## The gap

Identity on an Agent Card answers *who is this agent*. Nothing answers *is this agent's track
record real, or a server-side claim I have to trust*. A "reputation pointer" field is only as
trustworthy as whether a third party can independently confirm the feed it points at hasn't been
silently edited, backdated, or forked (a different history shown to different requesters).

The shape proposed in the discussion: a typed field carrying `issuer`/`scheme`/`ref`, a verifying
key, an anchored `committed_at`, a content-addressed export with a **monotonic head commitment**,
a **published head location** (so a fork is publicly catchable, not just server-claimed), and an
**explicit genesis marker** distinguishing "start of chain" from a missing predecessor a naive
walker could misread.

## What this checks

That shape, populated with a real, live entry from invinoveritas's own `/ledger` — entry #40, the
documented root its hash-chain starts from — not a hand-built example:

```
issuer                  : invinoveritas
scheme                  : https://api.babyblueviper.com/ledger#chain-v1
ref                     : https://api.babyblueviper.com/ledger/40
verifying_key           : 6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7
committed_at            : 1783121760   (Bitcoin OTS block time, precedence=true)
head_commitment         : 4969c7c18949e50f72be14f8087cf856564ac7354b127473a219d92bac3662d3
published_head_location : [relay.damus.io, nos.lol, relay.primal.net]
genesis_marker.value    : 09c790b34b51e22a0d4a0bd9c393d7e0c5891129038f83676a85e2b45f0316d2
```

```
python3 check_reputation_pointer.py      # zero-dependency, offline
```

Four things recompute from bytes:

1. **content-addressed** — `content_hash = sha256(canonical_json(record))` re-derives from the
   embedded record and matches the declared value.
2. **monotonic head** — `head_hash = sha256(content_hash + '|' + prev_head_hash)` chains this entry
   to the one before it.
3. **genesis marker** — entry #40's `prev_head_hash` equals `sha256('invinoveritas-ledger-genesis:
   before-entry-40')`, an explicit, checkable constant. A naive chain-walker hitting a missing
   predecessor and a walker hitting this exact hash learn different things: the first can't tell
   "chain not started yet" from "history was truncated"; the second can, because the genesis value
   is a public, fixed, checkable string, not an absence.
4. **tamper-sensitive** — editing the record after the fact moves `content_hash`, and therefore
   `head_hash`, and therefore every subsequent entry's own `head_hash` (not exercised in this
   single-entry example, but the propagation is structural — each entry embeds the previous head).

## Honest scope

This checks the content/head-chain recompute mechanically, from bytes, offline — same scope
boundary as every other example in this repo. It does **not** re-verify the OTS Bitcoin proof or
the underlying Nostr schnorr signature here; both are exercised by invinoveritas's own conformance
suite and `/verify-proof`, not duplicated in this offline example. What's checked is stated, what
isn't is named, not left implicit.

## Why this took a month

The original design comment on #1962 said "I'll draft the typed pointer field... and open a PR
against the Agent Card extension." That undersold what's actually involved: a formal A2A Agent
Card extension isn't a PR against this docs repo — it's a separate, `ext-`-prefixed repository
under the `a2aproject` org, going through the project's own governance tiers
(see [Extension and Protocol Binding Governance](https://a2a-protocol.org/latest/topics/extension-and-binding-governance/)).
That's a real, larger commitment than the original comment implied, not something to open solo in
a single pass.

What's shippable now, honestly: a concrete, live, recomputable worked example of the proposed
field shape — this. It's not the formal extension; it's the reference groundwork a formal proposal
would cite, built against real data instead of a placeholder schema.
