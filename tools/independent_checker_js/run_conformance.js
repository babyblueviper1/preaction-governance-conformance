#!/usr/bin/env node
/**
 * run_conformance.js — the conformance bar, asserted with THIS independent JS checker.
 *
 * Same assertion shape as run_conformance.py (the original Python runner), but every recompute
 * below goes through verify.js, not verifier.py — this is the CI gate that keeps the second
 * checker honest: if this file and run_conformance.py ever disagree on a fixture's declared
 * expected_overall/expected_failure_reason, CI goes red on THIS runner without needing the
 * Python one to also fail, proving the two are genuinely checked independently, not one silently
 * riding on the other's green.
 *
 * Exit 0 iff every fixture matches its own declared expectation exactly.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { verifyFixture } = require('./verify.js');

const FIXTURES_DIR = path.join(__dirname, '..', '..', 'fixtures');
const SKIP = new Set(['trust_policy.json', 'live_confirmed_anchor.json']);

function main() {
  const files = fs.readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith('.json') && !SKIP.has(f))
    .sort();

  const failures = [];
  for (const file of files) {
    const fx = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, file), 'utf8'));
    const r = verifyFixture(fx);
    const expectPass = fx.expected_overall === 'pass';
    const expectReason = fx.expected_failure_reason || null;

    if (r.overall_pass !== expectPass) {
      failures.push(`${file}: overall_pass=${r.overall_pass} expected ${expectPass}`);
      continue;
    }
    if (expectPass) {
      console.log(`  ✓ ${file}: PASS (all five invariants join)`);
      continue;
    }
    if (r.failure_reason !== expectReason) {
      failures.push(`${file}: failed with ${JSON.stringify(r.failure_reason)}, expected ${JSON.stringify(expectReason)}`);
      continue;
    }
    const broken = Object.entries(r.suites).filter(([, s]) => s.pass === false).map(([n]) => n);
    if (broken.length !== 1) {
      failures.push(`${file}: ${broken.length} broken suites [${broken.join(', ')}], expected exactly 1`);
      continue;
    }
    console.log(`  ✓ ${file}: FAIL (${expectReason}) — exactly one broken join, others pass`);
  }

  console.log('-'.repeat(64));
  if (failures.length) {
    console.log(`CONFORMANCE BAR NOT MET (independent JS checker) — ${failures.length} issue(s):`);
    for (const f of failures) console.log(`    ✗ ${f}`);
    process.exit(1);
  }
  console.log(`CONFORMANCE BAR MET (independent JS checker) — ${files.length} fixtures verify to their declared expectations.`);
  console.log('Recomputed from spec text + fixture bytes alone, in a different language, importing');
  console.log('nothing from verifier.py or _bip340_nostr.py — a real second checker, not an adapter.');
}

main();
