"""Minimal RFC-8785-style JSON Canonicalization Scheme (JCS) — pure stdlib.

Canonical form for the value subset used by action-ref preimages and profile docs:
objects (keys sorted by Unicode code point), strings, integers, booleans, null, arrays.
Output is the UTF-8 byte string an action_ref / profile_id is the SHA-256 of.

Scope note (honest): object keys are sorted by Unicode code point. RFC 8785 specifies
UTF-16 code-unit ordering, which differs only for keys containing characters outside the
Basic Multilingual Plane (surrogate pairs). For ASCII/BMP keys — every key in these
fixtures and in the autogen#7353 preimages — the two orderings are identical. A production
profile doc should state which ordering it pins; this demo pins code-point and says so.
"""
from __future__ import annotations

import json


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k])
                              for k in sorted(v.keys())) + "}"
    raise TypeError(f"non-canonicalizable type: {type(v).__name__}")
