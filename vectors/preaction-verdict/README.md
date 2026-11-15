# vectors/preaction-verdict

Conformance cases for readers of an independent **pre-action verdict**: a record, signed by a reviewer before an agent acts, saying what it
concluded about the proposed action. A relying party needs to know three things before it credits one: the trusted issuer signed it, it
is about *this* action, and it was issued *before* the action ran.

- `READER-CONTRACT.md`: the eight steps a reader applies, and what they establish and do not.
- `cases.json`: 13 cases: five real verdicts from the public ledger, eight refusals.
- `reader.py`: a reference reader, stdlib only (`bip340.py` is the BIP-340 reference algorithm in pure Python).
- `gen.py`: rebuilds the refusals, `cases.json` and `MANIFEST.json` byte for byte; the TEST-ONLY key comes from a public recipe.
- `MANIFEST.json`: SHA-256 of every file.

```
python3 reader.py      # 13/13 cases match, exit 0
python3 gen.py         # same bytes on every run
```

Write your reader from `READER-CONTRACT.md` before you open `reader.py` or the expected answers, and say so when you report a result.
