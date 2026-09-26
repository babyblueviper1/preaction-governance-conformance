# MUSUBI second offer (a2a-offer-v0) to horizonshield.dev

`babyblueviper_offer_0001.json`: built and signed with HS's `offer_sign.py` (stdlib + cryptography, no network), using our agreement
key (public key `poTpqz0G34FMkZ1okV/fd5Dcvq7mCO4v1+qOgqBsje4=`, served at https://api.babyblueviper.com/keys/agreement.json).
- File sha256 `23d12501d61122c5ab6e4bb03b3cf3915c117ea9d9988439739e834b2bfff526`; offer record_sha256 (signing bytes)
  `42bfa20d8e498740d16c15e1facaac7c6f0b1a7b1cb1f0c7d157ee4785ea1f57`.
- Beacon: Bitcoin block 968650 `00000000000000000001854f11c4d247dba6f61a9e9742a225c78ab328220ff0` -- after block 968542, which anchors
  HS's sealed decision rule (HS ledger entry 56, claim `2fa877f4…`, rule record `c92bf886…`).
- Terms (HS's proposal, kept unchanged): witness_walk, payment_jpy 0, max_hops 1, data_access public_endpoint, expiry_height 980000.
- Both signatures (offer + role statement `{role: witness, contractor_of: e15c0188…}`) re-verified independently before publishing.

`nenrin_mirror_manifest_2026-09-26.json`: our run of HS's `mirror-v0/mirror.py` (at 84592d52): 57 ledger entries, 4 objects, 0 problems.
Its sha256 includes `mirrored_at`, so two honest mirrors never produce the same file hash; compare the canonical manifest WITHOUT
`mirrored_at` (`1cf9c1ea70a40d83f6dd64e92a6ad1604e37652e78523e1eae72a4384f90547c`) or the entries alone
(`251f0598b7bf67c84771db0e44d72d7e32b2be0c39ebc6ec4c34bb31d3669089`, range 1..57).
