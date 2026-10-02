# Cross-layer call_digest vectors

Joined from [microsoft/autogen#7405](https://github.com/microsoft/autogen/issues/7405) (GuardrailProvider
RFC) and [giskard09/argentum-core](https://github.com/giskard09/argentum-core)'s `action_ref` spec
(pinned commit `c277309b0d51dd3dca87d3c7c07688a80021a467` — reference confirmed in
[issuecomment-5934214515](https://github.com/microsoft/autogen/issues/7405#issuecomment-5934214515)).

Two primitives came up on that thread for correlating records about one tool call across independent
layers (a provider, a policy gate, an executor — none of which necessarily share code or even see the
same fields):

- **`action_ref`** = `sha256(JCS({agent_id, action_type, scope, timestamp}))` — correlates every record
  about one attempt. No arguments in the preimage.
- **`call_digest`** = `sha256(JCS({tool_name, arguments}))` — binds what the call actually *was*.
  Recomputable by a layer that never sees `agent_id` or `scope` (a bare policy gate, for instance).

They're deliberately different primitives, not duplicates of each other or of giskard09's
`original_args_digest`/`effective_args_digest` (which bind args alone, without `tool_name`).

## The joins (A-C) and the serializer check (D)

| Vector | What it proves |
|---|---|
| **A** — provider approve / gate deny | Two independently-emitted records about the identical call can be confirmed to be about the identical call (`call_digest` matches), even when they disagree on verdict. |
| **B** — rewrite before dispatch | A call revised between proposal and dispatch produces two different `call_digest`s, exactly as it produces two different arg digests — checked as two independent confirmations of the same rewrite, not one. |
| **C** — not_reached | A call that never reached an inner layer carries no `call_digest` at all for that layer — absence is the correct signal, not a bug. This is the `not_reached` marker shape proposed and shipped earlier on the same thread ([issuecomment-5299618444](https://github.com/microsoft/autogen/issues/7405#issuecomment-5299618444) / [5299678449](https://github.com/microsoft/autogen/issues/7405#issuecomment-5299678449), `babyblueviper1/invinoveritas` commit `bd06127`, `integrations/autogen/governed_workbench.py`). |
| **D** — number canonicalization | `call_digest` must hash RFC 8785 JCS, not a language's default JSON text. 14 argument objects (5 where Python `json.dumps` differs from ECMAScript `JSON.stringify`: `1e-7`, `-0`, `100.0`, floats above 2^53, exponent forms), canonical strings produced by Node and reproduced byte for byte by the stdlib `rfc8785.py`. The preimage member name (`arguments` as in A-C, or `tool_input`) is not pinned by the RFC text yet, so both digests are listed per case. |

`shared_context`'s `action_ref`, `authorization_ref`, and both args digests are reused from giskard09's
pinned fixture and **recomputed from the same preimages here**, not copied as opaque strings — a break
in either repo's convention surfaces as a mismatch in this check too.

```bash
python3 check_cross_layer.py
```

Zero-dependency, offline, asserts parity + all three joins + tamper-sensitivity + the RFC 8785 number cases, exit 0 on pass.
