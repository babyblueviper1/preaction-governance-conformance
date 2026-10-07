// invinoveritas verdict component (action_evaluation), run through the unmodified runtime. Uses only the published contract.
// Fixtures: two real verdict proofs from https://api.babyblueviper.com/review (sign=true), issued 2026-10-07 on the canonical JSON of
// (a) the sim's approved refund (verdict approve_with_concerns) and (b) the same refund for EUR 4,000,000 (verdict reject).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { APS, APS_CLAIMS, ROOT, pinFromDisk, request, setup } from './helpers.ts'

const ID = 'invinoveritas/verdict-check'
const C = { auth: 'invinoveritas.verdict_authentic', covers: 'invinoveritas.verdict_covers_action', permits: 'invinoveritas.verdict_permits_action' }
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
