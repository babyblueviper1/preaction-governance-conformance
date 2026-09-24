# Cold implementation of draft-krausz-verification-state-02 §5.3 / §5.4.1: findings against the text

Written from the draft text only (https://www.ietf.org/archive/id/draft-krausz-verification-state-02.txt), with no
reference code and no explanation outside the draft, per x402-foundation/tsc#4. Implementation:
`tools/evidence_set_check.py` (stdlib only). Tests: `test_evidence_set.py` (16). Live run: `run_live_ledger.py`.

Each finding is a place where two careful implementers could reasonably diverge. The choice made here is stated so a
divergence can be traced to a reading and not to a bug. Ordered by how much I think they matter.

## F12: what "resolved" requires (highest impact)
§5.4.1 defines `resolved` only as "when the step's evidence requirements are met". (c) says a partial set resolves
`unknown`. (d) says a held-but-differing item "resolves unknown for that item". Nothing says what a **fully pinned set
whose content the verifier does not hold** resolves to. Steps (a) and (b) pass, and (d) is "answerable only by a verifier
that holds it". Reading 1: `resolved`, because the receipt is internally consistent. Reading 2: `unknown`, because no
offline recomputation was performed. The two give opposite answers to the question a relying party most wants
answered. There's a related gap: (d) resolves *per item*, but the step emits one token, and the rule for combining
them isn't stated.
**Choice here:** `resolved` only when fully pinned, the root recomputes, and the verifier held matching bytes for every
item. Anything else that isn't malformed resolves `unknown`.
**Suggest:** state it explicitly and say how per-item results combine into the step token.

## F11: no reason token for a held item that matches
(d) requires "a per-item reason for every entry in sources" and names `content_not_held` and `content_differs`. A
pinned item whose held bytes match has no named reason. **Choice here:** `content_matches`. **Suggest:** name it.

## F3: `snippet_sha256_absent_when_pinned` only fires when the root is non-null
The condition is specified inside (b), which begins "If evidence_root is non-null". A receipt with a pinned entry whose
`snippet_sha256` is null **and** `evidence_root: null` never reaches (b). It is still malformed, because a null root
with `pinned_count > 0` breaks §5.3.1, but under a condition the text doesn't name. So one defect gets reported under
two different names depending on another member. **Choice here:** check it in (a), per entry, unconditionally.

## F2: consistency violations with no named condition
§5.4.1(a) requires reporting "the specific violated condition named in the rule it failed". These §5.3.1 rules name
none:
- `pinned_count` ≠ the count of pinned entries
- `pinned_count > source_count`
- `source_count` ≠ `len(sources)` when non-zero
- declared `fully_pinned` inconsistent
- `evidence_root` non-null with zero pinned
- `evidence_root` null with pinned items

**Choice here:** `pinned_count_mismatch`, `source_count_mismatch`, `fully_pinned_mismatch`,
`evidence_root_present_with_no_pinned_items`, `evidence_root_absent_with_pinned_items`.

## F1: other entry-level MUSTs with no named condition
Each of these is stated as malformed (or follows from a MUST) but has no reported condition:
- `unpinned_reason` absent or outside its domain (the text says "malformed; gate decision = halt", with no name)
- `content_kind` absent or invalid on a pinned entry, or present on an unpinned one
- `snippet_sha256` not 64 lowercase hex
- `url` absent or not a string
- an entry that is not an object
- `resource_sha256` malformed

Names chosen are in the code. Interop suffers most here: two conformant verifiers will emit different strings for the
same receipt.

## F4: a digest on an unpinned entry
`snippet_sha256` is "... or null if not pinned". It isn't said whether a non-null digest on `pinned: false` is
malformed, or just ignored. The distinctness rule assumes it is null ("For an unpinned entry snippet_sha256 is null").
**Choice here:** malformed (`snippet_sha256_present_when_unpinned`). A digest implies the issuer held the bytes, and
the possession rule then requires pinning.

## F5: "No member may contain an octet 0x00" is stated as a fact
§5.3.3 presents it as the reason delimiter injection is unreachable. But a JSON string can carry U+0000, and nothing
validates it. **Choice here:** malformed (`member_contains_nul`). **Suggest:** make it a rule with a named condition,
or the injection argument doesn't hold.

## F6: canonical `retrieved_at` form vs a valid instant
The lexical form is fixed (UTC, `Z`, three fractional digits), but not whether `2026-02-30T25:61:00.000Z` passes.
**Choice here:** it must also be a valid date and time (second 60 allowed, per RFC 3339).

## F7: unrecognized `evidence_set_version`
§5.3.1 defines only `ao-evidence-set-v1` and doesn't say what a verifier does with any other value (halt, resolve
`unknown`, or ignore). **Choice here:** malformed.

## F8: condition name mismatch
The `resource_sha256` rule reports `snippet_digest_present_for_full_resource`, but the offending member is
`resource_sha256`, not the snippet digest. Implemented as written; flagged for -03.

## F9: `sources` absent or not an array
Only the empty array is named (`evidence_set_names_no_sources`). **Choice here:** absent or non-array folds into the
same condition.

## F10: set-level `retrieved_at` absent
There is a "Fallback when a count is declared absent" for the three counts, but none for the set-level `retrieved_at`,
though it can be derived the same way. **Choice here:** derived and not halted, by analogy with the counts. Readings
could differ.

## What held up without ambiguity
- the leaf and node preimages (hex text in the leaf, raw octets in the node), with a test pinning both byte layouts
- odd-node promotion without duplication
- single-leaf termination
- canonical sort order
- the entry-distinctness rule, including the pinned/unpinned pair and the "same content at a different time is not a
  duplicate" case
- the absent-counts fallback
- "no evidence_set resolves unknown and does not fail"

## Live run (`run_live_ledger.py`)
Real retrievals, at run time, of three content-addressed records served by `api.babyblueviper.com/record/<sha256>`.
The URL names the sha256 of the served bytes, which gives an independent cross-check of `snippet_sha256`. A fourth
retrieval returned 404 and is recorded unpinned (`no_content_returned`). Results:

| case | resolution | per-item |
|---|---|---|
| partial set (3 pinned + 1 no content), all held | unknown | matches ×3, content_not_held |
| fully pinned, all held | resolved | matches ×3 |
| fully pinned, nothing held | unknown | content_not_held ×3 (the F12 choice) |
| fully pinned, one held file differs | unknown | content_differs, matches ×2 |

`evidence_root` is identical across the partial and full sets, because unpinned items contribute nothing, as §5.3.3
requires. These results are self-consistent only: there is no independent implementation to cross-check the root
against yet. That is the next test: run both implementations on the same `payload.json`.
