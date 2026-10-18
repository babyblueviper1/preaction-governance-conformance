# commitment_anchor: draft OBS-06 text and conformance vectors

Proposed for [raknor-ai/agent-governance-standard#2](https://github.com/raknor-ai/agent-governance-standard/issues/2) (v1.1, Observability evidence field set). CC0-1.0.

## Problem

A timestamp written by the recording party is set by the party being assessed. A record written, or rewritten, after its outcome is known passes integrity checks and every other field in the set. An agent that logged its authorization after seeing the result looks the same as one that logged it before.

## Draft text (OBS-06, evidence field set)

**commitment_anchor** (RECOMMENDED; REQUIRED for any record that asserts it existed before its outcome).
A commitment of the record to a clock the recording party does not control. It contains:

- `mechanism`: the anchor type, for example `rfc3161`, `transparency-log` or `opentimestamps-bitcoin`.
- `digest` and `digest_rule`: the digest that was anchored, and how a verifier recomputes it from the record.
  `digest_rule` MUST name a deterministic procedure: a named canonicalization and hash (for example `nip01-event-id`, or JCS (RFC 8785) then SHA-256), so that any two implementations of the same `digest_rule` produce the same digest from the same record. A rule that leaves the serialization open (key order, whitespace, number format) establishes nothing.
  The verifier recomputes the digest from the record's fields. A digest the record states about itself (a Nostr `id`, a `hash` field) is not a recompute: it can be left at the old value after the content is edited. For `nip01-event-id` the input is the UTF-8 bytes of `[0,pubkey,created_at,kind,tags,content]` with no whitespace and NIP-01's escaping (only `\n \" \\ \r \t \b \f` are escaped; other characters are written as they are). `content` is hashed exactly as it stands: if it holds JSON, it is not decoded and re-serialized first.
- `proof_ref`: where the proof can be retrieved. Verifying the proof MUST NOT require trusting the recording party.
- `anchor_time`: the time the proof attests, as the mechanism reports it.
- `anchor_time_rule`: how the latest possible anchoring time (the ceiling) is derived. One of:
  - `header_time_plus_tolerance`: ceiling = `anchor_time + anchor_time_tolerance_s`. Right where the clock states its own accuracy (an RFC 3161 TSA's `accuracy`). For Bitcoin it is only a convention: consensus bounds how far a header time may run *ahead* of real time (about two hours), which is a floor, and nothing caps how far it may lag. Header times are not even ordered by height.
  - `later_median`: ceiling = `anchor_ceiling_time`, the median time of the 11 blocks after the anchor block (Bitcoin Core's `mediantime` of anchor height + 11), with `anchor_ceiling_source` naming them. Every later block was mined after the anchor, so if a majority of those 11 timestamps are honest, the median is at or after the anchor's real time. That is an assumption, but a stated one, and no constant is needed. The RECOMMENDED rule for a Bitcoin anchor whose outcome is not on the same chain.
  - `height`: the outcome is itself ordered by the same chain (a transaction, a block hash, another anchored record). Precedence holds if `anchor_height` is strictly below `outcome_height`. No time and no tolerance: `anchor_time` and `outcome_time` are not compared under this rule, and the outcome's header time may be earlier than the anchor's. Use it whenever it applies.
  Absent means `header_time_plus_tolerance`, for records written before this field existed. `header_time_plus_tolerance` stays allowed for a Bitcoin anchor, but the verdict then rests on a field the miner chose: `control-backdated-header-moves-the-ceiling` moves the ceiling 3558 s within what consensus allows, and `later_median` does not move. A verifier SHOULD report which rule a verdict used.
- `anchor_time_tolerance_s`: the clock's stated uncertainty, for `header_time_plus_tolerance`. Absent means inputs missing, not zero.
- `anchor_height`: the anchor's block height, for `height`.

Fields on the record itself, next to `commitment_anchor`, not inside it:

- `outcome_time`: when the outcome happened (Unix seconds).
- `outcome_height`: the outcome's block height, for `height`.
- `asserts_precedence`: `true` if the record claims it existed before its outcome. Absent means it does not claim it.
- `does_not_assert`: the claims the record declares it does not make.

**Rule.** A record MAY assert that it existed before its outcome only if its ceiling, under its `anchor_time_rule`, is strictly earlier than the outcome (or, for `height`, its anchor height is strictly below the outcome's). A rule whose inputs are missing establishes nothing. Otherwise:

- the record MUST NOT assert precedence; and
- it MUST list `precedence_before_outcome` in `does_not_assert`, so the limitation is declared rather than silently absent (the same move `coverage_denominator` makes for completeness).

A record whose anchored digest does not recompute from the record has no anchor for this rule.

**Results.** A verifier returns one result per record, checked in this order, and stops at the first that applies:

1. `ANCHOR_DOES_NOT_COVER_RECORD`: the digest does not recompute from the record.
2. `NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM`: the record asserts precedence and the rule does not establish it (this covers a record that also fails to declare the limitation).
3. `NONCONFORMING_UNDECLARED_LIMITATION`: precedence is not established, not asserted, and `precedence_before_outcome` is not in `does_not_assert`.
4. `CONFORMING`: none of the above. Each result also carries `precedence_established` (true or false).

Precedence is about *when* the record was fixed, not *how* its claims were obtained. An anchor that predates the outcome does not upgrade the record's `observation_vantage`: a record built from data the executor could influence stays that, however early it was anchored. The two are assessed separately.

The field is mechanism-neutral. Any externally verifiable existence proof satisfies it, at different cost and trust points.

## Vectors

`vectors.json` has the requested pair, four negative controls, five vectors for the other two ceiling rules, and three backdated-header vectors. `kind` is a label only; some `negative_control` vectors are expected CONFORMING. `check.py` is stdlib only:

```
python3 check.py            # 14/14 agree
ots verify -d a42205d7e39c684f0aa43f80fe7ea1aa8e180df93ff46e82b5bff95b70c663e9 38.ots
# Success! Bitcoin block 955810 attests existence as of 2026-06-28 UTC
```

| id | what it pins | expected |
|---|---|---|
| `anchor-before-outcome` | real anchor 2026-06-28 (block 955810), real outcome 2026-07-03 | CONFORMING, precedence established |
| `anchor-after-outcome-declared` | same anchor, outcome before it, limitation declared | CONFORMING, not established |
| `control-claims-precedence-after-outcome` | late anchor, but the record claims precedence | NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM |
| `control-late-anchor-silent` | late anchor, limitation not declared | NONCONFORMING_UNDECLARED_LIMITATION |
| `control-outcome-inside-tolerance` | outcome 1 h after the block time, inside the 2 h tolerance | NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM |
| `control-anchor-does-not-cover-record` | one word of the record changed after anchoring | ANCHOR_DOES_NOT_COVER_RECORD |
| `later-median-outcome-inside-old-tolerance` | outcome at T + 3600, later-median ceiling T + 3093 (blocks 955811-955821) | CONFORMING, precedence established |
| `control-later-median-ceiling-after-outcome` | outcome before the later-median ceiling | NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM |
| `control-later-median-ceiling-missing` | `later_median` declared, no ceiling given | NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM |
| `height-outcome-in-later-block` | outcome in block 955811, whose header time is earlier than 955810's | CONFORMING, precedence established |
| `control-height-same-block` | outcome in the anchor's own block | NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM |
| `control-backdated-header-moves-the-ceiling` | synthetic header time 1782651081, the earliest consensus allows for 955810 (MTP of 955799-955809 + 1) | CONFORMING, precedence established |
| `control-honest-header-same-outcome` | the same outcome under the real header time | NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM |
| `later-median-independent-of-the-header-field` | the same outcome under `later_median` | CONFORMING, precedence established |

Each control is load-bearing. Removing any one of these from `check.py` makes at least one vector fail:

- the tolerance;
- the digest recompute;
- the undeclared-limitation check;
- the unsupported-claim check.

## Sources and limits

- The record is entry 38 of a public verdict ledger (a signed pre-action verdict; digest = its NIP-01 event id). Its OpenTimestamps proof is `38.ots`, also served at `https://api.babyblueviper.com/ledger/38/ots`.
- The second vector and the controls reuse that real anchor. Their outcome times are **synthetic**, chosen to land before or just after the anchor. The real "after" cases on that ledger are trading records, kept out of a standards corpus on purpose.
- `check.py` evaluates the rule. It does not verify the proof itself: run the mechanism's own verifier (`ots verify`, an RFC 3161 client, an inclusion-proof checker) and compare its attested time to `anchor_time`.
- The ceiling rules and the later-median / height vectors follow Toshikatsu Oga's reading on probityai/agent-evidence#32 (header time is a floor, not a ceiling; 955811's time precedes 955810's). His numbers recompute from public headers: median of 955811-955821 = 1782657732 = T + 3093; median of the 11 before 955810 = 1782651080. `check.py` takes `anchor_ceiling_time` and heights as given; fetch the headers to check them.
- The three backdated-header vectors, the Results section and the field-location and digest text come from his blind run at bd70521 (a reader written from the README, the expect-stripped vectors and `38.ots` only; `precedence_established` agreed 11/11): ogasurfproject-jpg/horizon-shield@33c22f5a, `workers/hs-ledger/nenrin/commitment-anchor-reader-v0/` (`blind/GAPS.md`, `backdated/backdated_vectors.json`).
- Disclosure: we operate that ledger. The field and the rule do not depend on it.
