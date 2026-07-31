# DEILS leg-2 — held-content-behind-commitment reveal check

Executable conformance for Merlini's (trustless-ai) held-content-behind-commitment design —
the DEILS "leg 2" architecture resolving the tension between invinoveritas's always-public
`/ledger` and DEILS's privacy-outside-sessions default. Pinned live in the trustless-ai Telegram
group 2026-07-23 (msg_id 1623 for case ownership, 1632/2111-2112 for the canonicalization +
ref-string-format correction).

## The design

Two layers, deliberately split:

- **Existence** — a `commitment_hash` (the content's canonical hash) plus a monotonic sequence
  position — is **mandatory-public and non-suppressible by construction**. A missing entry is a
  visible gap, not a quiet omission.
- **Content** — the actual proved substance — is **optional-private**: held server-side, disclosed
  on demand, and verified against the already-published commitment when it is revealed.

## Reference implementation

`invinoveritas`'s `/prove` endpoint (`routes/execution.py`):

- `POST /prove {"action_id": ..., "disclose": false}` — publishes only
  `{proof_id, ledger_position, commitment_hash, status: "content_withheld"}`. The signed proof
  content stays server-side, untransmitted (never broadcast to Nostr, never returned in the API
  response) until revealed.
- `POST /prove/{proof_id}/reveal {"content": {...}}` — binds the given content to the published
  `commitment_hash`. Free, no-auth: the check is a pure function of
  `(stored commitment_hash, revealed content)`, never caller identity, so any third party can
  confirm the bind without trusting whoever discloses.

Every public surface that could otherwise leak withheld content through a side door is guarded:
`GET /attestations/{proof_id}` and `GET /attestations` redact content while `reveal_state ==
"content_withheld"`, and `POST /verify-proof {"proof_id": ...}` refuses to resolve a withheld
proof_id into its signed event (the event's own `content` field IS the full payload — that path
would otherwise leak it before a real reveal).

## States

| State | Meaning |
|---|---|
| `content_withheld` | Nothing disclosed yet — **pending, not a failure**. |
| `content_bound` | Revealed content hashes to the published commitment. |
| `content_commitment_mismatch` | **Terminal, fail-closed.** A *positive* evidence state (tampering on reveal, or a bad original commitment) — not an absence, and not itself a verdict on malice vs. error. Preserves `{committed_hash, revealed_content, recomputed_hash}` so the disagreement is legible. |

## Canonicalization

`sha256(JCS(parsed(content)))`, ref string = `"sha256:"` + 64 lowercase hex (**not** `"0x"` + hex —
the earlier `0x` form was superseded live, msg_id 2111/2112, before any vectors were cut). JCS here
is RFC 8785: recursively sorted object keys, compact separators, raw UTF-8 (not `\uXXXX`-escaped) —
matches invinoveritas's own `decision_ref` convention and the receipt canonicalization already used
elsewhere in this stack.

**The input to JCS is always the PARSED (language-native) value, never the wire bytes as-received**
(pinned explicitly, Pavlo, 2026-07-31, after case 6 below showed why): a served `\uXXXX`-escaped
JSON string is byte-for-byte valid, parseable JSON, but it is NOT the canonical form — only
re-canonicalizing the *parsed* value is. Putting `parsed()` in the definition itself, rather than
leaving it implicit and catching the failure only via a test vector, means a correct implementation
cannot fall into the wire-bytes trap in the first place; the vector (case 6) now exists to catch a
*non*-conforming implementation, not to carry the rule's own domain boundary.

## The 6 pinned cases (vectors.json)

1. `content_bound` — happy path, content hashes to the commitment.
2. `canonicalization_near_miss` — same content, different top-level key order → **must still
   bind** (proves the shared canonical JSON does the work, not string-equality).
3. `single_byte_flip` — one byte of revealed content changed → **must be**
   `content_commitment_mismatch` (proves the check says NO loudly, no silent pass).
4. `content_withheld` — nothing disclosed yet → `pending`, not a failure.
5. `deep_nested_key_shuffle_adversarial` — a *deliberately-wrong-obvious-answer* case, distinct
   from case 2: keys are shuffled at **multiple nested levels**, not just the top level. A checker
   that only sorts top-level keys (or does a raw string diff instead of a recursive JCS
   canonicalization) would get this wrong. Needed to prove the checker genuinely re-derives from
   the canonicalization rule, not a shape that only happens to look independent.
6. `escaped_non_ascii_wire_trap` (added 2026-07-31, Pavlo) — makes the "canonicalize, don't hash
   the served content" trap below **falsifiable, not just documented**. Carries a real non-ASCII
   `reviewer_note` field plus a pinned `wire_representation_ascii_escaped` string (what a plain
   `json.dumps()`, the stdlib's `ensure_ascii=True` default, would actually serve for that content).
   The checker pins BOTH halves: (a) hashing that wire string's raw bytes directly **must not**
   match the commitment — the trap is real, not a hypothetical — and (b) `json.loads()`-ing it
   back and re-canonicalizing via the shared JCS **must still bind** — the correct path handles it
   fine. A checker that only implemented case 1-5 could pass every one of them while still hashing
   served wire bytes directly and silently mis-verifying real non-ASCII content in production.

## Independent second checker

Merlini built `trustless-ai/deils/conformance/deils-reveal-v0/reveal_check.py` **before these
vectors existed** — genuinely blind, derived from the spec alone (msg_id 1624/1627). Run it against
`vectors.json` to diff its verdicts against `check_deils_leg2.py`'s, chronicle-continuity-gate
style: two independent implementations converging on the same 5 verdicts is the actual point of a
"don't trust, recompute" profile.

```bash
python3 check_deils_leg2.py
```

## A real trap found live (2026-07-30, Merlini, blind end-to-end verification)

Independently verifying against a real live commitment (not just the pinned vectors), Merlini
found a genuine wire-level gotcha worth documenting: **canonicalize, don't hash the served
content.** The commitment is `sha256(JCS(content))` computed over raw UTF-8 bytes
(`ensure_ascii=False` — msg_id 2111/2112). But content served back to a caller may travel through
a JSON layer that re-escapes non-ASCII into `\uXXXX` sequences (the default behavior of a plain
`json.dumps()`, and plausibly a Nostr relay's own re-serialization if the content is fetched from
a relay rather than directly from the issuing API). Hashing that literal escaped wire string
produces the WRONG digest — a byte-level verifier must first JSON-parse the served string back to
its real value, then re-encode as raw UTF-8, before hashing. Confirmed on invinoveritas's own REST
API: it serves the correct raw-UTF-8 form (Starlette's `JSONResponse` uses `ensure_ascii=False`),
so this specific trap does not fire there — but it is a general Nostr/JSON-relay risk, not an
implementation detail of any one server, and any consumer fetching a proof's content from a relay
rather than the origin should canonicalize before hashing, never hash the wire bytes directly.

Pavlo (trustless-ai group, 2026-07-31) named the sharper framing: this is "a byte-domain ambiguity,
not just a documentation trap — same class as a fixture recipe that pins the hash operation but
not which bytes feed it." Case 6 above turns his proposed vector into an executable, falsifiable
check rather than leaving it as a README caveat.

