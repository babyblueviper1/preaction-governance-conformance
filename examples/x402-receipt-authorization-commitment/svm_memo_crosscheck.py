"""Second, independent implementation of the `svm-memo` authorization method proposed in x402-foundation/x402#3830
(holistis). Written from the §5.6.2 text alone, stdlib only, no code from the proposer's kit.
Inputs are the ones in holistis/tokenizen examples/x402-svm-memo-commitment (5bad82c, run-vectors.mjs commit-A/commit-B);
the expected values are what that kit's commit() returns. Two implementations agreeing from the text is the point.
    python3 svm_memo_crosscheck.py      -> 2/2 agree
"""
import hashlib, sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_32(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    out = b"\0" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(out) != 32:
        raise ValueError(f"not a 32-byte Solana pubkey: {s}")
    return out


def commit(mint: str, payer: str, memo_bytes: bytes, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex[2:] if salt_hex.lower().startswith("0x") else salt_hex)
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    identifier = hashlib.sha256(memo_bytes).digest()          # §5.6.2: variable native identifier -> SHA-256
    pre = (b"x402-receipt-authorization/0" + b"\x00" + b"svm-memo" + b"\x00"
           + b58_32(mint) + b58_32(payer) + identifier + salt)
    return "0x" + hashlib.sha256(pre).hexdigest()


MINT, PAYER = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
CASES = [
    ("commit-A", b"9f1c0b7a4e52d386", "0x8f2b1d4e6a0c93758e1fb2a4c6d80e5f3719ab42cd6e805f1a3b7c9d2e4f6081",
     "0xffb8966ec1d5565bd0580f4f007d99c0162a88476f69b3e79cb95246b4175c59"),
    ("commit-B", b"c3d82a5f17b40e69", "0x2c7e91a3b5d70f486192c3e5a7b90d2f4816ae53bd7f916021c4d8e3f507a2b9",
     "0x39b03f72b6a9e3c9412be66f524950f168a63c08d64d6048aa82919851256c92"),
]

if __name__ == "__main__":
    ok = 0
    for name, memo, salt, want in CASES:
        got = commit(MINT, PAYER, memo, salt)
        ok += got == want
        print(("AGREE " if got == want else "DIFFER") + f" {name} {got}")
    print(f"{ok}/{len(CASES)} agree")
    sys.exit(0 if ok == len(CASES) else 1)
