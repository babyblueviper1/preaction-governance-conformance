// invinoveritas verdict component (action_evaluation), run through the unmodified runtime. Uses only the published contract.
// Fixtures: two real verdict proofs from https://api.babyblueviper.com/review (sign=true), issued 2026-10-07 on the canonical JSON of
// (a) the sim's approved refund (verdict approve_with_concerns) and (b) the same refund for EUR 4,000,000 (verdict reject).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { APS, APS_CLAIMS, ROOT, pinFromDisk, request, setup } from './helpers.ts'

const ID = 'invinoveritas/verdict-check'
const C = { auth: 'invinoveritas.verdict_authentic', covers: 'invinoveritas.verdict_covers_action', permits: 'invinoveritas.verdict_permits_action',
            target: 'invinoveritas.verdict_covers_target' }
const V = JSON.parse(readFileSync(join(ROOT, 'test/fixtures/invinoveritas/verdicts.json'), 'utf8'))
const bytes = (o: unknown) => new Uint8Array(Buffer.from(JSON.stringify(o)))
const apsRequired = APS_CLAIMS.map(claim => ({ component: APS, claim }))
const LONG = 10 * 365 * 86400   // fixtures are signed once; freshness has its own test

async function env(config: Record<string, unknown>, as: 'required' | 'optional' = 'required') {
  const pin = pinFromDisk(join(ROOT, 'adapters/invinoveritas-verdict'), { config })
  const refs = [C.auth, C.covers, C.permits].map(claim => ({ component: ID, claim }))
  return setup({ extraComponents: { [ID]: pin }, required: as === 'required' ? [...apsRequired, ...refs] : apsRequired, optional: as === 'optional' ? refs : [] })
}
const claims = (e: Awaited<ReturnType<typeof setup>>, op: string) =>
  Object.fromEntries((e.rt.provenance(op) as any).admissions.at(-1).claims.filter((c: any) => c.component === ID).map((c: any) => [c.claim, c.status]))

test('I01 a real verdict on this exact action, accepted verdict: admitted, all three claims established, verdict kept as evidence', async () => {
  const e = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: LONG })
  try {
    const { req } = request(e); (req.evidence as Record<string, Uint8Array>)[ID] = bytes(V.approved_refund.event)
    assert.equal((await e.rt.submit(req)).status, 'provider_confirmed')
    assert.deepEqual(claims(e, req.operation_id), { [C.auth]: 'established', [C.covers]: 'established', [C.permits]: 'established' })
    assert.equal(Buffer.from(e.rt.store.evidence(req.operation_id, ID, 'check:0')!).toString(), JSON.stringify(V.approved_refund.event))
  } finally { await e.close() }
})

test('I02 the default policy accepts only approve: approve_with_concerns is refused before any side effect', async () => {
  const e = await env({ max_age_s: LONG })
  try {
    const { req } = request(e); (req.evidence as Record<string, Uint8Array>)[ID] = bytes({ event: V.approved_refund.event })   // the {event} wrapper is accepted too
    const r = await e.rt.submit(req)
    assert.equal(r.status, 'refused')
    assert.deepEqual((r as any).reasons, [`required_claim_not_established:${ID}#${C.permits}:verdict_approve_with_concerns`])
    assert.equal(e.provider.requests, 0)
  } finally { await e.close() }
})

test('I03 a genuine verdict issued on a different action (the EUR 4M refund) does not cover this one', async () => {
  const e = await env({ accept_verdicts: ['approve', 'approve_with_concerns', 'reject'], max_age_s: LONG })
  try {
    const { req } = request(e); (req.evidence as Record<string, Uint8Array>)[ID] = bytes(V.reckless_refund.event)
    const r = await e.rt.submit(req)
    assert.equal(r.status, 'refused')
    assert.deepEqual(claims(e, req.operation_id), { [C.auth]: 'established', [C.covers]: 'not_established', [C.permits]: 'not_established' })
    assert.equal(e.provider.requests, 0)
  } finally { await e.close() }
})

test('I04 the reject verdict on the EUR 4M refund, presented for that refund, is refused on the verdict', async () => {
  const e = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: LONG })
  try {
    const { req } = request(e, { ...V.reckless_refund.action.args }); (req.evidence as Record<string, Uint8Array>)[ID] = bytes(V.reckless_refund.event)
    const r = await e.rt.submit(req)
    assert.equal(r.status, 'refused')
    assert.ok((r as any).reasons.includes(`required_claim_not_established:${ID}#${C.permits}:verdict_reject`), JSON.stringify((r as any).reasons))
    assert.equal(e.provider.requests, 0)
  } finally { await e.close() }
})

test('I05 tampering: verdict edited to approve, wrong signer, flipped signature bit, are each refused on authenticity', async () => {
  const ev = V.approved_refund.event
  const edited = { ...ev, content: ev.content.replace('"approve_with_concerns"', '"approve"') }
  const otherKey = { ...ev, pubkey: 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9' }
  const flipped = { ...ev, sig: ev.sig.slice(0, -1) + (ev.sig.endsWith('0') ? '1' : '0') }
  const cases: [unknown, string][] = [[edited, 'event_id_does_not_recompute'], [otherKey, 'event_id_does_not_recompute'], [flipped, 'signature_invalid']]
  for (const [evid, reason] of cases) {
    const e = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: LONG })
    try {
      const { req } = request(e); (req.evidence as Record<string, Uint8Array>)[ID] = bytes(evid)
      const r = await e.rt.submit(req)
      assert.equal(r.status, 'refused')
      assert.ok((r as any).reasons.includes(`required_claim_not_established:${ID}#${C.auth}:${reason}`), JSON.stringify((r as any).reasons))
      assert.equal(e.provider.requests, 0)
    } finally { await e.close() }
  }
  // a correctly recomputed id over a foreign pubkey still fails, on the signer
  const { createHash } = await import('node:crypto')
  const k = otherKey as any
  k.id = createHash('sha256').update(JSON.stringify([0, k.pubkey, k.created_at, k.kind, k.tags, k.content])).digest('hex')
  const e = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: LONG })
  try {
    const { req } = request(e); (req.evidence as Record<string, Uint8Array>)[ID] = bytes(k)
    const r = await e.rt.submit(req)
    assert.ok((r as any).reasons.includes(`required_claim_not_established:${ID}#${C.auth}:signer_is_not_the_pinned_key`), JSON.stringify((r as any).reasons))
  } finally { await e.close() }
})

test('I06 no verdict presented, malformed bytes, and a stale verdict are refused with distinct reasons', async () => {
  const e1 = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: LONG })
  try {
    const { req } = request(e1)
    const r = await e1.rt.submit(req)
    assert.ok((r as any).reasons.includes(`required_claim_not_established:${ID}#${C.permits}:no_verdict_presented`), JSON.stringify((r as any).reasons))
  } finally { await e1.close() }
  const e2 = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: LONG })
  try {
    const { req } = request(e2); (req.evidence as Record<string, Uint8Array>)[ID] = new Uint8Array(Buffer.from('not json'))
    const r = await e2.rt.submit(req)
    assert.ok((r as any).reasons.includes(`required_claim_failed:${ID}#${C.auth}:evidence_not_json`), JSON.stringify((r as any).reasons))   // malformed input is `failed`, not `not_established`
  } finally { await e2.close() }
  const e3 = await env({ accept_verdicts: ['approve', 'approve_with_concerns'], max_age_s: 60 })
  try {
    const { req } = request(e3); (req.evidence as Record<string, Uint8Array>)[ID] = bytes(V.approved_refund.event)
    const r = await e3.rt.submit(req)
    assert.ok((r as any).reasons.includes(`required_claim_not_established:${ID}#${C.permits}:verdict_older_than_max_age`), JSON.stringify((r as any).reasons))
    assert.equal(e3.provider.requests, 0)
  } finally { await e3.close() }
})

test('I07 as an optional component it never blocks: admitted without a verdict, statuses recorded', async () => {
  const e = await env({ max_age_s: LONG }, 'optional')
  try {
    const { req } = request(e)
    assert.equal((await e.rt.submit(req)).status, 'provider_confirmed')
    assert.deepEqual(claims(e, req.operation_id), { [C.auth]: 'not_established', [C.covers]: 'not_established', [C.permits]: 'not_established' })
  } finally { await e.close() }
})

// Target coverage (I08-I11). The runtime's refund workflow has no target and its approval binds the exact refund args, so these
// call the component's check() directly. The verdicts are signed here with a BIP-340 TEST key (pubkey override in config), the
// same event shape /review returns; the production key path is covered by I01-I07 with real verdicts.
const { createAdapter, subjectOf } = await import('../adapters/invinoveritas-verdict/adapter.ts')
const { createHash } = await import('node:crypto')
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn, N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
type Pt = [bigint, bigint] | null
const md = (a: bigint, m = P) => ((a % m) + m) % m
const pw = (b: bigint, e: bigint): bigint => { let r = 1n; b = md(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n } return r }
const ad = (a: Pt, b: Pt): Pt => {
  if (a === null) return b; if (b === null) return a
  if (a[0] === b[0] && md(a[1] + b[1]) === 0n) return null
  const l = a[0] === b[0] && a[1] === b[1] ? md(3n * a[0] * a[0] * pw(2n * a[1], P - 2n)) : md((b[1] - a[1]) * pw(b[0] - a[0], P - 2n))
  const x = md(l * l - a[0] - b[0]); return [x, md(l * (a[0] - x) - a[1])]
}
const ml = (p: Pt, k: bigint): Pt => { let r: Pt = null; for (let i = 255; i >= 0; i--) { r = ad(r, r); if ((k >> BigInt(i)) & 1n) r = ad(r, p) } return r }
const G: Pt = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n]
const b32 = (x: bigint) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex')
const int = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'))
const th = (tag: string, ...parts: Uint8Array[]) => { const t = createHash('sha256').update(tag).digest(); const h = createHash('sha256').update(t).update(t); for (const x of parts) h.update(x); return h.digest() }
/** BIP-340 signing, zero aux randomness (spec section "Default Signing"). Test key only. */
function sign(sk: bigint, msg: Buffer): Buffer {
  const Pk = ml(G, sk)!; const d = Pk[1] % 2n === 0n ? sk : N - sk
  const t = Buffer.from(b32(d).map((v, i) => v ^ th('BIP0340/aux', Buffer.alloc(32))[i]))
  const k0 = md(int(th('BIP0340/nonce', t, b32(Pk[0]), msg)), N); const R = ml(G, k0)!; const k = R[1] % 2n === 0n ? k0 : N - k0
  const e = md(int(th('BIP0340/challenge', b32(R[0]), b32(Pk[0]), msg)), N)
  return Buffer.concat([b32(R[0]), b32(md(k + e * d, N))])
}
const SK = md(int(createHash('sha256').update('invinoveritas-verdict target test key').digest()), N)
const TEST_PUB = b32(ml(G, SK)![0]).toString('hex')
function verdictOn(action: unknown, verdict = 'approve') {
  const ev: any = { pubkey: TEST_PUB, created_at: 1791407712, kind: 30078, tags: [['schema', 'invinoveritas.verdict_proof.v1']],
                    content: JSON.stringify({ artifact_hash: subjectOf(action).action_sha256, verdict }) }
  ev.id = createHash('sha256').update(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])).digest('hex')
  ev.sig = sign(SK, Buffer.from(ev.id, 'hex')).toString('hex')
  return ev
}
const A = 'https://a.example/mcp', B = 'https://b.example/mcp'
const act = (target?: string) => ({ tool: 'refund', args: { payment_id: 'pay_A', amount_minor: 4000, currency: 'EUR', ...(target ? { target } : {}) } })
async function run(config: Record<string, unknown>, action: unknown, ev: unknown, runtimeTarget?: string) {
  const a = createAdapter({ config: { pubkey: TEST_PUB, max_age_s: LONG, ...config }, secrets: {}, fetch })
  const input: any = { operation_id: 'op', workflow: 'refund', action: action as any, evidence: bytes(ev), now: '2026-10-09T00:00:00.000Z' }
  if (runtimeTarget !== undefined) input.target = runtimeTarget   // CheckInput.target, proposed for v1 (#177)
  const out = await a.check!(input)
  return Object.fromEntries(out.claims.map((c: any) => [c.claim, [c.status, c.reason]]))
}

test('I08 target inside the hashed action and equal to the declared target: covered, subject reports action hash and target', async () => {
  const r = await run({ declared_target: A }, act(A), verdictOn(act(A)))
  assert.deepEqual(r[C.auth], ['established', undefined])
  assert.deepEqual(r[C.covers], ['established', `subject:action_sha256=${subjectOf(act(A)).action_sha256}`])
  assert.deepEqual(r[C.target], ['established', `subject:target=${A}`])
  assert.equal(r[C.permits][0], 'established')
})

test('I09 target outside the hashed action: the verdict still covers the action, the target is not_established', async () => {
  const r = await run({ declared_target: A }, act(), verdictOn(act()))
  assert.equal(r[C.covers][0], 'established')
  assert.deepEqual(r[C.target], ['not_established', 'target_not_in_hashed_action'])
  const none = await run({}, act(A), verdictOn(act(A)))   // in the hash, but no declared target to compare with
  assert.deepEqual(none[C.target], ['not_established', 'no_runtime_target'])
})

test('I10 a verdict issued for target A, presented for an action sent to target B, fails coverage', async () => {
  const r = await run({ declared_target: B }, act(B), verdictOn(act(A)))
  assert.deepEqual(r[C.covers], ['not_established', 'verdict_is_for_a_different_action'])
  assert.deepEqual(r[C.permits], ['not_established', 'verdict_is_for_a_different_action'])
  assert.deepEqual(r[C.target], ['not_established', 'verdict_is_for_a_different_action'])
})

test('I11 the action and its verdict name target A while the workflow declares B: the target claim is refused', async () => {
  const r = await run({ declared_target: B }, act(A), verdictOn(act(A)))
  assert.equal(r[C.covers][0], 'established')
  assert.deepEqual(r[C.target], ['not_established', 'verdict_target_is_not_the_declared_target'])
})

test('I12 a runtime target (CheckInput.target, proposed v1) is compared instead of config, and wins over a disagreeing config', async () => {
  const ok = await run({}, act(A), verdictOn(act(A)), A)
  assert.deepEqual(ok[C.target], ['established', `subject:target=${A}`])
  const signedAruntimeB = await run({ declared_target: A }, act(A), verdictOn(act(A)), B)   // config says A, the runtime dispatches to B
  assert.equal(signedAruntimeB[C.covers][0], 'established')
  assert.deepEqual(signedAruntimeB[C.target], ['not_established', 'verdict_target_is_not_the_runtime_target'])
})

test('I13 v1 draft structured subject (aeoess/federation-port#5 section 5): subject.target whenever the verdict covers the action and its target is valid', async () => {
  const raw = async (action: unknown, ev: unknown, runtimeTarget?: string) => {
    const a = createAdapter({ config: { pubkey: TEST_PUB, max_age_s: LONG }, secrets: {}, fetch })
    const input: any = { operation_id: 'op', workflow: 'refund', action: action as any, evidence: bytes(ev), now: '2026-10-09T00:00:00.000Z' }
    if (runtimeTarget !== undefined) input.target = runtimeTarget
    return Object.fromEntries((await a.check!(input)).claims.map((c: any) => [c.claim, c]))
  }
  const ok = await raw(act(A), verdictOn(act(A)), A)
  assert.deepEqual([ok[C.target].status, ok[C.target].subject], ['established', { target: A }])
  assert.equal(ok[C.target].reason, `subject:target=${A}`)                     // the v0 stand-in is still there
  for (const c of [C.auth, C.covers, C.permits]) assert.equal(ok[c].subject, undefined)   // only the target-bound claim reports one
  const mis = await raw(act(A), verdictOn(act(A)), B)                          // fail closed, still says what the verdict covers
  assert.deepEqual([mis[C.target].status, mis[C.target].reason, mis[C.target].subject], ['not_established', 'verdict_target_is_not_the_runtime_target', { target: A }])
  const none = await raw(act(A), verdictOn(act(A)))
  assert.deepEqual([none[C.target].status, none[C.target].reason, none[C.target].subject], ['not_established', 'no_runtime_target', { target: A }])
  const slash = await raw(act(A + '/'), verdictOn(act(A + '/')), A)           // exact string: no trailing-slash normalization
  assert.deepEqual([slash[C.target].status, slash[C.target].subject], ['not_established', { target: A + '/' }])
  const other = await raw(act(B), verdictOn(act(A)), B)                        // verdict on another action: nothing covered, nothing reported
  assert.deepEqual([other[C.target].status, other[C.target].subject], ['not_established', undefined])
  const absent = await raw(act(), verdictOn(act()), A)
  assert.deepEqual([absent[C.target].reason, absent[C.target].subject], ['target_not_in_hashed_action', undefined])
  for (const bad of ['', 'https://a.example/\uD800', 'https://a.example/\uDC00x']) {   // empty, lone high and lone low surrogate
    const action = { tool: 'refund', args: { payment_id: 'pay_A', amount_minor: 4000, currency: 'EUR', target: bad } }
    const r = await raw(action, verdictOn(action), bad)
    assert.equal(r[C.covers].status, 'established')
    assert.deepEqual([r[C.target].status, r[C.target].reason, r[C.target].subject], ['not_established', 'target_not_valid', undefined])
  }
  const pair = 'https://a.example/\uD83D\uDE00'                                // a well-formed surrogate pair is a valid target
  const pr = await raw(act(pair), verdictOn(act(pair)), pair)
  assert.deepEqual([pr[C.target].status, pr[C.target].subject], ['established', { target: pair }])
  const long = 'https://a.example/' + 'x'.repeat(200)                         // past the 120-unit reason bound: the subject is whole
  const lr = await raw(act(long), verdictOn(act(long)), long)
  assert.deepEqual([lr[C.target].status, lr[C.target].subject], ['established', { target: long }])
  assert.equal(lr[C.target].reason, `subject:target_sha256=${createHash('sha256').update(long).digest('hex')}`)
})
