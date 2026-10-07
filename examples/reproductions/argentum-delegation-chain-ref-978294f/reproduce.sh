#!/usr/bin/env bash
# Independent reproduction of giskard09/argentum-core#123 (TKCollective/argentum-core @ 978294f):
# delegation-chain-ref mid-hop-revocation (4 vectors) + partial-chain-recovery (5 vectors), run with the repo's own reference
# verifier, plus byte-for-byte regeneration from each build.py and the repo's test suite.
set -euo pipefail
PIN=978294f24a5cb43ef834e1e541f41c33d2729961
W="$(mktemp -d)"
git clone -q https://github.com/TKCollective/argentum-core "$W/ac" && git -C "$W/ac" checkout -q "$PIN"
git -C "$W/ac" merge-base --is-ancestor 7b92265 HEAD && echo "built on 7b92265"
git -C "$W/ac" merge-base --is-ancestor c277309b HEAD && echo "includes c277309b"
python3 -m venv "$W/v" && "$W/v/bin/pip" install -q -r "$W/ac/requirements.txt" rfc8785 pytest
D="$W/ac/examples/conformance/delegation-chain-ref"
for s in mid-hop-revocation partial-chain-recovery; do
  echo "== $s"
  (cd "$D/$s" && "$W/v/bin/python" verify.py | tail -6)
  (cd "$D/$s" && before=$(sha256sum vectors.json | cut -c1-64) && "$W/v/bin/python" build.py >/dev/null && after=$(sha256sum vectors.json | cut -c1-64) \
     && echo "vectors.json sha256 $before -> rebuild $after" && [ "$before" = "$after" ] && echo "rebuild byte-identical")
done
(cd "$W/ac" && "$W/v/bin/python" -m pytest -q tests/ | tail -1)
