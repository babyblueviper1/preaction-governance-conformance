#!/usr/bin/env bash
# Reproduce: run this adapter through federation-port's UNMODIFIED core at the pinned commit, plus BIP-340's official vectors.
# Needs git + Node >= 22 (type stripping). Node 24 runs it without the flag.
set -euo pipefail
PIN=3a2f6ce
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT   # leave nothing behind (clones, venv, node_modules)
mkdir -p "$W/tmp" && export TMPDIR="$W/tmp"   # the test suites' own temp files go inside $W too
git clone -q https://github.com/aeoess/federation-port "$W/fp" && git -C "$W/fp" checkout -q "$PIN"
mkdir -p "$W/fp/adapters/invinoveritas-verdict" "$W/fp/test/fixtures/invinoveritas"
cp "$HERE"/adapter.ts "$HERE"/bip340.ts "$HERE"/manifest.json "$W/fp/adapters/invinoveritas-verdict/"
cp "$HERE"/test/invinoveritas-verdict.test.ts "$W/fp/test/"
cp "$HERE"/test/fixtures/verdicts.json "$W/fp/test/fixtures/invinoveritas/"
cd "$W/fp" && npm ci --silent
FLAG="--experimental-strip-types"; node -e 'process.exit(+process.versions.node.split(".")[0] >= 24 ? 0 : 1)' && FLAG=""
node $FLAG scripts/seal.ts adapters/invinoveritas-verdict
git diff --quiet -- src && echo "core unmodified (src/ clean)"
node $FLAG --disable-warning=ExperimentalWarning --test --test-concurrency=1 'test/*.test.ts'
node $FLAG --disable-warning=ExperimentalWarning "$HERE/test/bip340_vectors.ts"
