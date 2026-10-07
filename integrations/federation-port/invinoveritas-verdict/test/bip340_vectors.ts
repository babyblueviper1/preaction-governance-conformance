import { readFileSync } from 'node:fs'
import { verifyBip340 } from '../bip340.ts'
const rows = readFileSync(new URL('./bip340-test-vectors.csv', import.meta.url), 'utf8').trim().split('\n').slice(1)
let pass = 0, fail = 0, skipped = 0
for (const r of rows) {
  const [idx, , pk, , msg, sig, result] = r.split(',')
  if (msg.length !== 64) { skipped++; continue }   // BIP-340 vectors 15-18 use non-32-byte messages; our ids are always 32 bytes
  let got = false
  try { got = verifyBip340(Buffer.from(pk, 'hex'), Buffer.from(msg, 'hex'), Buffer.from(sig, 'hex')) } catch { got = false }
  const want = result.trim() === 'TRUE'
  if (got === want) pass++; else { fail++; console.log('MISMATCH', idx, 'want', want, 'got', got) }
}
console.log(`BIP-340 official vectors: ${pass} pass, ${fail} fail, ${skipped} skipped (non-32-byte msg)`)
