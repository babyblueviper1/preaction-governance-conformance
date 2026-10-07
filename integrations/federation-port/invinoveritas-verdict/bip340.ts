// BIP-340 Schnorr verification over secp256k1, no dependencies (BigInt + node:crypto SHA-256).
// Verification only: no secret keys are handled here.
import { createHash } from 'node:crypto'

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const G: Pt = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
               0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n]
type Pt = [bigint, bigint] | null

const mod = (a: bigint, m = P) => ((a % m) + m) % m
function pow(b: bigint, e: bigint, m = P): bigint {
  let r = 1n; b = mod(b, m)
  while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n }
  return r
}
const inv = (a: bigint) => pow(a, P - 2n)
function add(a: Pt, b: Pt): Pt {
  if (a === null) return b
  if (b === null) return a
  if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null
  const l = a[0] === b[0] && a[1] === b[1] ? mod(3n * a[0] * a[0] * inv(2n * a[1])) : mod((b[1] - a[1]) * inv(b[0] - a[0]))
  const x = mod(l * l - a[0] - b[0])
  return [x, mod(l * (a[0] - x) - a[1])]
}
function mul(p: Pt, k: bigint): Pt {
  let r: Pt = null
  for (let i = 255; i >= 0; i--) { r = add(r, r); if ((k >> BigInt(i)) & 1n) r = add(r, p) }
  return r
}
const toInt = (b: Uint8Array) => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'))
const toBytes = (x: bigint) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex')
function tagged(tag: string, ...parts: Uint8Array[]): Buffer {
  const th = createHash('sha256').update(tag).digest()
  const h = createHash('sha256').update(th).update(th)
  for (const p of parts) h.update(p)
  return h.digest()
}
function liftX(x: bigint): Pt {
  if (x >= P) return null
  const c = mod(x * x * x + 7n)
  const y = pow(c, (P + 1n) / 4n)
  if (y * y % P !== c) return null
  return [x, y % 2n === 0n ? y : P - y]
}

/** True iff `sig` (64 bytes) is a valid BIP-340 signature by x-only `pubkey` (32 bytes) over `msg` (32 bytes). */
export function verifyBip340(pubkey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pubkey.length !== 32 || msg.length !== 32 || sig.length !== 64) return false
  const Pk = liftX(toInt(pubkey))
  if (Pk === null) return false
  const r = toInt(sig.subarray(0, 32)), s = toInt(sig.subarray(32, 64))
  if (r >= P || s >= N) return false
  const e = mod(toInt(tagged('BIP0340/challenge', toBytes(r), toBytes(Pk[0]), msg)), N)
  const R = add(mul(G, s), mul([Pk[0], mod(-Pk[1])], e))
  return R !== null && R[1] % 2n === 0n && R[0] === r
}
