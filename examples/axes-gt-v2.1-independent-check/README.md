# Independent check: AXES Golden Trace gt-v2.1

An independent reproduction of the AXES corpus of record **gt-v2.1** (tag `corpus/2026-10-12-gt-v2.1`, commit `c72b620`), written from the
published text (`docs/09`, `docs/09a`, `VERIFY.md`, the bundle README). It uses invinoveritas's own RFC 8785 canonicaliser, the same one
our signed work-acceptance records use, inlined in `axes_independent_check.py`. No AXES code is imported or run.

```
git clone --branch corpus/2026-10-12-gt-v2.1 --depth 1 https://github.com/magentixai/axes.git axes-gt-v2.1
python3 -I axes_independent_check.py axes-gt-v2.1
```

Standard library only. Output: [`run_gt-v2.1.txt`](run_gt-v2.1.txt).

## Result

| Bundle | Envelope hashes | `previous_envelope_hash` links | Chain head | Files | Bundle digest |
|---|---|---|---|---|---|
| `golden-trace` | 76/76 | 76/76 | `cbd1a73e…59f1` matches | 38/38 | `e922486b…164e` matches |
| `golden-trace-ind` | 76/76 | 76/76 | `5ca428ea…19dd6` matches | 40/40 | `dd01b56c…bb31` matches |

`bundle_manifest_hash` is reproduced as `sha256(JCS(manifest.files))`. Of the three readings tried, it is the only one that matches.

## One divergence between the corpus and the text

`docs/09a` §4 lists three exclusions from the envelope hash: `integrity.signature`, `integrity.envelope_hash`, and `recorded_at`
(`recipient_stamped`). The corpus hashes are reproduced only with `recorded_at` **inside** the hash. With it excluded, as §4 reads, 0 of
76 envelope hashes match in either bundle. The signature field in the corpus is also named `integrity.envelope_signature`, not
`integrity.signature`. Either the note or the corpus should move, and a third implementation following §4 as written will fail every
envelope.

## Limits

The canonicaliser is RFC 8785 for objects, arrays, strings, integers, booleans and null, with key order by code point. That equals JCS
when no float is in hash scope and every key is ASCII. The script checks both on every hashed value and stops if either fails, and on
this corpus neither fails (AXES pins 0 floats in hash scope). Signatures are stubbed and in-trace anchors simulated in the corpus itself.
This check covers the hashes, chain, files and bundle digest, not the release anchors (RFC 3161 / OpenTimestamps) or the profile vectors.
