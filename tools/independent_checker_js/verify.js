#!/usr/bin/env node
/**
 * verify.js — an INDEPENDENTLY-implemented second checker for the five joined invariants
 * (canonical_envelope / chain_invariant / admission_invariant / anchoring_existence /
 * anchoring_precedence), written from the spec text and fixture shape alone.
 *
 * WHY THIS EXISTS (Rul1an, crewAI#4877, real critique against our own /conformance registry):
 * an "adapter" that points a shared checker at a new endpoint tests integration, not code-
 * independence — a real second checker has to independently re-derive the invariants from the
 * spec text, never importing or delegating to the original. This file does not require, import,
 * or read verifier.py or _bip340_nostr.py at any point — the BIP-340/NIP-01 crypto below is a
 * from-scratch implementation in a different language (JavaScript, not Python), using only
 * Node's built-in `crypto` (SHA-256) and native BigInt (secp256k1 field/curve arithmetic). If
 * this file and the Python verifier ever disagree on a fixture's overall verdict, that is a real
 * bug in one of them, not a formatting difference — that's the entire point of a second checker.
 *
 * Five invariants (verbatim intent from README.md, re-derived independently here):
 *   canonical_envelope   — sha256(canonical_bytes_utf8) must equal the fixture's declared hash
 *   chain_invariant      — pre_action.envelope_hash, terminal.executed_envelope_hash, and the
 *                           recomputed envelope hash must all match, and action_ref must not split
 *   admission_invariant  — the verdict_event must be a genuine BIP-340 schnorr signature (id
 *                           integrity + sig verify), its content must bind artifact_hash to the
 *                           recomputed envelope hash, and its pubkey must be independent (in
 *                           trust_policy.independent_verifier_pubkeys AND not the actor's pubkey)
 *   anchoring_existence  — an anchor must be present and its commitment_digest must equal the
 *                           admission event's own id (the anchor binds THIS admission, not just
 *                           some admission)
 *   anchoring_precedence — only assessable once existence holds; the accepted anchor point's
 *                           block_time must be strictly before terminal_outcome_time, and an
 *                           anchor explicitly marked precedence:false never counts as ordering
 *                           proof no matter how early its block_time reads
 *
 * Run:
 *   node verify.js ../../fixtures/positive.json ../../fixtures/negative_*.json
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');

// ---------------------------------------------------------------------------------------------
// secp256k1 field + curve arithmetic, pure BigInt, no library. Standard curve constants.
// ---------------------------------------------------------------------------------------------
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modInverse(a, m) {
  // Fermat's little theorem: a^(m-2) mod m, valid since P and N are both prime.
  return modPow(a, m - 2n, m);
}

function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
}

function pointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2, P) === 0n) return null; // point at infinity
  let lam;
  if (x1 === x2 && y1 === y2) {
    lam = mod(3n * x1 * x1 * modInverse(2n * y1, P), P);
  } else {
    lam = mod((y2 - y1) * modInverse(x2 - x1, P), P);
  }
  const x3 = mod(lam * lam - x1 - x2, P);
  const y3 = mod(lam * (x1 - x3) - y1, P);
  return [x3, y3];
}

function pointMul(point, scalar) {
  let result = null;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

function liftX(x) {
  // BIP-340: given x, find the point with EVEN y (x-only pubkeys are always the even-y choice).
  if (x >= P) return null;
  const ySq = mod(x * x % P * x + 7n, P); // y^2 = x^3 + 7 (secp256k1, a=0, b=7)
  let y = modPow(ySq, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== ySq) return null; // x is not on the curve
  if (y % 2n !== 0n) y = P - y;
  return [x, y];
}

function taggedHash(tag, ...msgParts) {
  const tagHash = crypto.createHash('sha256').update(tag, 'utf8').digest();
  const h = crypto.createHash('sha256');
  h.update(tagHash);
  h.update(tagHash);
  for (const part of msgParts) h.update(part);
  return h.digest();
}

function bytesToBigInt(buf) {
  return BigInt('0x' + buf.toString('hex'));
}

function bigIntToBytes32(n) {
  return Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
}

function schnorrVerify(msg32, pubkeyXBytes, sig64) {
  // BIP-340 verification, from the spec directly:
  //   1. lift_x(pubkey) -> P (fail if not on curve)
  //   2. r = sig[0:32] as int, s = sig[32:64] as int; fail if r >= P or s >= N
  //   3. e = int(tagged_hash("BIP0340/challenge", r || pubkey || msg)) mod N
  //   4. R = s*G - e*P; fail if R is infinity, R.y is odd, or R.x != r
  try {
    const P_point = liftX(bytesToBigInt(pubkeyXBytes));
    if (P_point === null) return false;
    const r = bytesToBigInt(sig64.subarray(0, 32));
    const s = bytesToBigInt(sig64.subarray(32, 64));
    if (r >= P || s >= N) return false;
    const eBytes = taggedHash('BIP0340/challenge', sig64.subarray(0, 32), pubkeyXBytes, msg32);
    const e = mod(bytesToBigInt(eBytes), N);
    const sG = pointMul([GX, GY], s);
    const eP = pointMul(P_point, mod(N - e, N)); // -e*P == (N-e)*P
    const R = pointAdd(sG, eP);
    if (R === null) return false;
    const [rx, ry] = R;
    if (ry % 2n !== 0n) return false;
    return rx === r;
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// NIP-01 event id: sha256(JSON.stringify([0, pubkey, created_at, kind, tags, content])), with
// the same field types the Python implementation declares — pubkey lowercased, integers coerced.
// ---------------------------------------------------------------------------------------------
function nostrEventId(event) {
  const serial = JSON.stringify([
    0,
    String(event.pubkey).toLowerCase(),
    Math.trunc(Number(event.created_at)),
    Math.trunc(Number(event.kind)),
    event.tags || [],
    String(event.content),
  ]);
  return crypto.createHash('sha256').update(serial, 'utf8').digest('hex');
}

function eventSignatureValid(ev) {
  try {
    if (nostrEventId(ev) !== ev.id) return false;
    const msg32 = Buffer.from(ev.id, 'hex');
    const pub = Buffer.from(ev.pubkey, 'hex');
    const sig = Buffer.from(ev.sig, 'hex');
    return schnorrVerify(msg32, pub, sig);
  } catch (e) {
    return false;
  }
}

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------------------------
// The five invariants.
// ---------------------------------------------------------------------------------------------
function verifyFixture(fx) {
  const suites = {};

  // canonical_envelope
  const ce = fx.canonical_envelope;
  const envelopeHash = sha256Hex(ce.canonical_bytes_utf8);
  const envOk = envelopeHash === ce.expected_envelope_hash;
  suites.canonical_envelope = {
    pass: envOk,
    code: envOk ? null : 'envelope_hash_mismatch',
    detail: `recomputed ${envelopeHash.slice(0, 16)} vs declared ${ce.expected_envelope_hash.slice(0, 16)}`,
  };

  // chain_invariant
  const pre = fx.chain.pre_action, term = fx.chain.terminal;
  const chainOk = pre.envelope_hash === envelopeHash
    && term.executed_envelope_hash === envelopeHash
    && pre.action_ref === term.action_ref;
  suites.chain_invariant = {
    pass: chainOk,
    code: chainOk ? null : 'chain_join_failed',
    detail: chainOk ? 'pre-action, terminal and envelope hashes join'
                     : 'pre-action / terminal / envelope hash mismatch or action_ref split',
  };

  // admission_invariant
  const adm = fx.admission;
  const ev = adm.verdict_event;
  const trust = fx.trust_policy.independent_verifier_pubkeys;
  const actor = pre.actor_pubkey;
  let admCode = null, admDetail = 'independent published key signed the bound envelope hash';
  if (!eventSignatureValid(ev)) {
    admCode = 'admission_signature_invalid';
    admDetail = 'event id/schnorr signature does not verify';
  } else {
    let bound = null;
    try { bound = JSON.parse(ev.content).artifact_hash; } catch (e) { /* leave null */ }
    if (bound !== envelopeHash) {
      admCode = 'verdict_binding_failed';
      admDetail = `verdict signs ${JSON.stringify(bound)}, not the proposed envelope hash`;
    } else if (ev.pubkey === actor) {
      admCode = 'admission_not_independent';
      admDetail = 'signer is the actor/executor (self-attested)';
    } else if (!trust.includes(ev.pubkey)) {
      admCode = 'key_different_but_identity_unproven';
      admDetail = 'signer differs from actor but is not a declared-independent identity';
    }
  }
  suites.admission_invariant = { pass: admCode === null, code: admCode, detail: admDetail };

  // anchoring_existence + anchoring_precedence
  const anc = fx.anchor || null;
  if (anc === null) {
    suites.anchoring_existence = {
      pass: false, code: 'ordering_unanchored',
      detail: 'no external existence proof — internal ordering only',
    };
    suites.anchoring_precedence = {
      pass: null, code: 'not_assessable',
      detail: 'no anchor, so pre-outcome ordering cannot be established',
    };
  } else if (anc.commitment_digest !== ev.id) {
    suites.anchoring_existence = {
      pass: false, code: 'anchor_commitment_mismatch',
      detail: 'anchor does not commit to this admission',
    };
    suites.anchoring_precedence = {
      pass: null, code: 'not_assessable',
      detail: 'anchor does not bind this admission, so ordering is not assessable',
    };
  } else {
    suites.anchoring_existence = {
      pass: true, code: null,
      detail: 'commitment externally anchored and bound to this admission',
    };
    if (anc.precedence === false) {
      suites.anchoring_precedence = {
        pass: false, code: 'existence_only_anchor',
        detail: 'anchor proves the commitment exists, but carries no pre-outcome (forward) stamp, '
               + 'so it does not establish it was made first',
      };
    } else if (anc.accepted_anchor_point.block_time >= anc.terminal_outcome_time) {
      suites.anchoring_precedence = {
        pass: false, code: 'late_commitment',
        detail: 'anchor accepted at/after the terminal outcome',
      };
    } else {
      suites.anchoring_precedence = {
        pass: true, code: null,
        detail: 'accepted anchor point strictly precedes the terminal outcome',
      };
    }
  }

  const overall = Object.values(suites).every((s) => s.pass === true);
  const firstFail = Object.values(suites).find((s) => s.pass === false);
  return {
    overall_pass: overall,
    failure_reason: firstFail ? firstFail.code : null,
    suites,
    envelope_hash: envelopeHash,
  };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('usage: node verify.js <fixture.json> [...]');
    process.exit(2);
  }
  let rc = 0;
  for (const path of args) {
    const fx = JSON.parse(fs.readFileSync(path, 'utf8'));
    const r = verifyFixture(fx);
    const verdict = r.overall_pass ? 'PASS' : `FAIL (${r.failure_reason})`;
    console.log(`${path.split('/').pop()}: ${verdict}`);
    for (const [name, s] of Object.entries(r.suites)) {
      const mark = s.pass === true ? '✓' : s.pass === false ? '✗' : '–';
      console.log(`    ${mark} ${name}: ${s.code || 'ok'} — ${s.detail}`);
    }
    if (!r.overall_pass) rc = 1;
  }
  process.exit(rc);
}

if (require.main === module) main();

module.exports = { verifyFixture, schnorrVerify, nostrEventId, sha256Hex };
