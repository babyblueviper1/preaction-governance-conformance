"""ERC-8409 quote digest + signature, from the spec text (PR #1990 @ 0ee33230)."""
from eth_utils import keccak
from eth_account import Account
from eth_account.messages import encode_typed_data

TYPES = {"ServicePaymentQuote": [{"name": n, "type": t} for n, t in [
    ("issuer", "address"), ("payer", "address"), ("recipient", "address"), ("asset", "address"), ("amount", "uint256"),
    ("requestScheme", "string"), ("requestHash", "bytes32"), ("quoteId", "bytes32"), ("validAfter", "uint64"), ("validUntil", "uint64")]]}
INT = {"amount", "validAfter", "validUntil"}

def typed(chain_id, q):
    msg = {k: (int(v) if k in INT else (bytes.fromhex(v[2:]) if k in ("requestHash", "quoteId") else v)) for k, v in q.items()}
    return {"domain": {"name": "Signed Service Payment Quotes", "version": "1", "chainId": int(chain_id)},
            "types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                                       {"name": "chainId", "type": "uint256"}], **TYPES},
            "primaryType": "ServicePaymentQuote", "message": msg}

def quote_digest(chain_id, q):
    m = encode_typed_data(full_message=typed(chain_id, q))
    return "0x" + keccak(b"\x19" + m.version + m.header + m.body).hex()

def sign(chain_id, q, key):
    return "0x" + Account.sign_typed_data(key, full_message=typed(chain_id, q)).signature.hex().removeprefix("0x")

def recover(chain_id, q, sig):
    return Account.recover_message(encode_typed_data(full_message=typed(chain_id, q)), signature=sig)
