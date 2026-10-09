// invinoveritas verdict component (action_evaluation). Checks, offline, that the caller presented an invinoveritas signed
// verdict (verdict_proof.v1, a NIP-01 event signed BIP-340 by the pinned invinoveritas key) issued on THIS exact action, and
// that the verdict is one the customer accepts. No network, no dependencies, no secrets. Written against src/contract only.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import type { Adapter, AdapterContext, CheckOutput, ClaimResult, Manifest } from '../../src/contract/types.ts'
import { verifyBip340 } from './bip340.ts'

const manifest: Manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'))
export const INVINOVERITAS_PUBKEY = '6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7'
const SCHEMA = 'invinoveritas.verdict_proof.v1'
const KIND = 30078
const C_AUTH = 'invinoveritas.verdict_authentic'
const C_COVERS = 'invinoveritas.verdict_covers_action'
const C_PERMITS = 'invinoveritas.verdict_permits_action'
const C_TARGET = 'invinoveritas.verdict_covers_target'
const REASON_MAX = 120   // the runtime's bound on a reason code

/** Sorted-key JSON, the same construction as the runtime's canonicalJson (the action bytes the verdict was issued on). */
function canonical(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v)
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('non_finite_number'); return JSON.stringify(v) }
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']'
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    return '{' + Object.keys(o).filter(k => o[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonical(o[k])).join(',') + '}'
  }
  throw new Error(`unsupported_type:${typeof v}`)
}
const sha256hex = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex')
const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/

type Event = { id: string; pubkey: string; created_at: number; kind: number; tags: string[][]; content: string; sig: string }

function all(status: ClaimResult['status'], reason: string, evidence: Uint8Array = new Uint8Array()): CheckOutput {
  return { evidence, claims: [C_AUTH, C_COVERS, C_PERMITS, C_TARGET].map(claim => ({ claim, status, reason })) }
}

/**
 * Subject fields this component can establish, read from the action bytes the verdict was issued on: the action hash always,
 * the target only when it is a member of the hashed action (args[target_field]). v0 has no subject field, so check() reports
 * these as the reason code of the established claim.
 */
export function subjectOf(action: unknown, targetField = 'target'): { action_sha256: string; target?: string } {
  const out: { action_sha256: string; target?: string } = { action_sha256: sha256hex(canonical(action)) }
  const args = (action as { args?: Record<string, unknown> } | null)?.args
  const t = args && typeof args === 'object' ? args[targetField] : undefined
  if (typeof t === 'string') out.target = t
  return out
}

export function createAdapter(ctx: AdapterContext): Adapter {
  const cfg = (ctx.config ?? {}) as { pubkey?: string; accept_verdicts?: string[]; max_age_s?: number; declared_target?: string; target_field?: string }
  const pubkey = (cfg.pubkey ?? INVINOVERITAS_PUBKEY).toLowerCase()
  const accept = cfg.accept_verdicts ?? ['approve']
  const maxAgeS = cfg.max_age_s ?? 900
  return {
    describe: () => manifest,
    async check(input): Promise<CheckOutput> {
      const bytes = input.evidence
      if (!bytes || bytes.byteLength === 0) return all('not_established', 'no_verdict_presented')
      let ev: Event
      try {
        const parsed = JSON.parse(Buffer.from(bytes).toString('utf8'))
        ev = (parsed && typeof parsed === 'object' && parsed.event) ? parsed.event : parsed
      } catch { return all('failed', 'evidence_not_json', bytes) }
      if (!ev || typeof ev !== 'object' || typeof ev.content !== 'string' || typeof ev.created_at !== 'number' || !Array.isArray(ev.tags)
          || typeof ev.id !== 'string' || typeof ev.sig !== 'string' || typeof ev.pubkey !== 'string') {
        return all('failed', 'evidence_not_a_signed_event', bytes)
      }
      // 1. authenticity: NIP-01 id recomputes, signed by the pinned key, is a verdict proof
      let auth: ClaimResult
      const recomputed = sha256hex(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))
      const schemaTag = ev.tags.some(t => Array.isArray(t) && t[0] === 'schema' && t[1] === SCHEMA)
      if (!HEX64.test(ev.id) || !HEX64.test(ev.pubkey) || !HEX128.test(ev.sig)) auth = { claim: C_AUTH, status: 'not_established', reason: 'malformed_event_fields' }
      else if (recomputed !== ev.id) auth = { claim: C_AUTH, status: 'not_established', reason: 'event_id_does_not_recompute' }
      else if (ev.pubkey !== pubkey) auth = { claim: C_AUTH, status: 'not_established', reason: 'signer_is_not_the_pinned_key' }
      else if (ev.kind !== KIND || !schemaTag) auth = { claim: C_AUTH, status: 'not_established', reason: 'not_a_verdict_proof' }
      else if (!verifyBip340(Buffer.from(ev.pubkey, 'hex'), Buffer.from(ev.id, 'hex'), Buffer.from(ev.sig, 'hex'))) auth = { claim: C_AUTH, status: 'not_established', reason: 'signature_invalid' }
      else auth = { claim: C_AUTH, status: 'established' }
      if (auth.status !== 'established') {
        return { evidence: bytes, claims: [auth, { claim: C_COVERS, status: 'not_established', reason: 'verdict_not_authentic' },
                                                  { claim: C_PERMITS, status: 'not_established', reason: 'verdict_not_authentic' },
                                                  { claim: C_TARGET, status: 'not_established', reason: 'verdict_not_authentic' }] }
      }
      let content: { artifact_hash?: unknown; verdict?: unknown }
      try { content = JSON.parse(ev.content) } catch { return all('failed', 'content_not_json', bytes) }
      // 2. coverage: the verdict was issued on the exact action the runtime will dispatch
      let subject: ReturnType<typeof subjectOf>
      try { subject = subjectOf(input.action, cfg.target_field) } catch { return all('failed', 'action_not_canonicalizable', bytes) }
      const covers: ClaimResult = content.artifact_hash === subject.action_sha256
        ? { claim: C_COVERS, status: 'established', reason: `subject:action_sha256=${subject.action_sha256}` }
        : { claim: C_COVERS, status: 'not_established', reason: 'verdict_is_for_a_different_action' }
      // 2b. target: established only when the target is inside the hashed action and equals the runtime's dispatch target.
      // The runtime target is CheckInput.target (proposed for v1 in #177); v0 has no such field, so config.declared_target
      // stands in for it there. When both are present the runtime's wins: config can't show where the executor dispatches.
      const runtimeTarget = (input as { target?: unknown }).target
      const dispatchTarget = typeof runtimeTarget === 'string' ? runtimeTarget : cfg.declared_target
      const fromRuntime = typeof runtimeTarget === 'string'
      let target: ClaimResult
      if (covers.status !== 'established') target = { claim: C_TARGET, status: 'not_established', reason: 'verdict_is_for_a_different_action' }
      else if (subject.target === undefined) target = { claim: C_TARGET, status: 'not_established', reason: 'target_not_in_hashed_action' }
      else if (typeof dispatchTarget !== 'string') target = { claim: C_TARGET, status: 'not_established', reason: 'no_runtime_target' }
      else if (subject.target !== dispatchTarget) target = { claim: C_TARGET, status: 'not_established', reason: fromRuntime ? 'verdict_target_is_not_the_runtime_target' : 'verdict_target_is_not_the_declared_target' }
      else {
        const r = `subject:target=${subject.target}`
        target = { claim: C_TARGET, status: 'established', reason: r.length <= REASON_MAX ? r : `subject:target_sha256=${sha256hex(subject.target)}` }
      }
      // 3. permission: accepted verdict, on this action, still fresh
      const nowMs = Date.parse(input.now)
      const expiresMs = (ev.created_at + maxAgeS) * 1000
      let permits: ClaimResult
      if (covers.status !== 'established') permits = { claim: C_PERMITS, status: 'not_established', reason: 'verdict_is_for_a_different_action' }
      else if (typeof content.verdict !== 'string' || !accept.includes(content.verdict)) permits = { claim: C_PERMITS, status: 'not_established', reason: `verdict_${String(content.verdict)}` }
      else if (!(nowMs <= expiresMs)) permits = { claim: C_PERMITS, status: 'not_established', reason: 'verdict_older_than_max_age' }
      else permits = { claim: C_PERMITS, status: 'established' }
      const out: CheckOutput = { evidence: bytes, claims: [auth, covers, permits, target] }
      if (permits.status === 'established') out.valid_until = new Date(expiresMs).toISOString()
      return out
    },
  }
}
