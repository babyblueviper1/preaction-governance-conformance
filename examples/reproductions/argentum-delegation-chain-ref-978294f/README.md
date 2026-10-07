# argentum-core delegation-chain-ref @ 978294f: independent reproduction

- **Set:** `mid-hop-revocation/` (4 vectors) and `partial-chain-recovery/` (5 vectors) under
  `examples/conformance/delegation-chain-ref/`, from TKCollective/argentum-core `978294f24a5cb43ef834e1e541f41c33d2729961`.
  This is opened as giskard09/argentum-core#123. It is built on giskard09 `main` at `7b92265`, which includes `c277309b`.
- **Run:** cold clone on our machine with Python 3.12.3 and a fresh venv (`requirements.txt` + `rfc8785` + `pytest`). Each set's
  own runner was used, and it loads the reference `verify.py` at that commit.
- **Result:**
  - mid-hop-revocation **4/4**. The differential holds: revocation metadata for `hops[1]` changes neither the passing nor the
    failing structural verdict.
  - partial-chain-recovery **5/5**.
  - Both `vectors.json` regenerate byte for byte from their `build.py` (sha256 `7be1c87c…d2da` and `f9efaff9…5a75`).
  - `pytest tests/` gives **222 passed, 4 skipped**, matching the authors' reported run.
- **One environment note:** a cold `pip install -r requirements.txt` at the repo root does not install `rfc8785`, which one other
  verifier imports (`evidence-anchor-static-analysis-v0`, which declares it in its own `requirements.txt`). Without it, the root
  `pytest` shows 221 passed and 1 failed. That failure is unrelated to this set.
- **Scope:** this confirms that the published verdicts come out of the published code at that commit. It does not test §7.5
  enforcement or cascade semantics, which the set deliberately excludes.

Rerun: `./reproduce.sh`. Our transcript: `transcript.txt`.
