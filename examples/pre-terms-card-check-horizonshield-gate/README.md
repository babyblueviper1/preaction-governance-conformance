# Pre-terms agent-card check: gate.horizonshield.dev

A signed record from the invinoveritas checker (`invinoveritas-checker-a4cecab2`, keys at
`https://api.babyblueviper.com/.well-known/invinoveritas-checker-keys.json`) of one agent card, made before any contract terms,
for the MUSUBI kit's pre-terms step (a2aproject/A2A discussion 2306; the kit pins `parties[].agent_card_sha256`).

- Card: `https://gate.horizonshield.dev/.well-known/agent-card.json`, bytes in `agent-card.json`, **sha256 `ada419468d732bdc0fbc13b692a0b36f9ee2a9560001f2375f0410fbd98dc88f`**
  (the same bytes are inside `observation.json` as `agent_card_base64`, with `agent_card_sha256`).
- Criteria committed 2026-10-21T16:15Z (`criteria.json`, `criteria.tsr`), then the probes, then the record (issued 16:17:53Z).
- `observation.json`: one A2A JSON-RPC `message/send` per declared skill, sent without credentials, plus a tokenless
  `POST /sweep`. Each probe records the request, HTTP status, response sha256 and a text excerpt. Client:
  `invinoveritas-pre-terms-check/0.1` (Cloudflare refuses the default Python client signature with error 1010; that is not the gate's auth).

## Findings (verdict `fail`)

| Criterion | Result | Finding |
|---|---|---|
| S1 declared skills answer | fail | All five probes got a JSON-RPC result without error, but over A2A `verify`, `conditions` and `lookup` answered with the register reading or a "send an MCP endpoint URL" prompt, not the function their descriptions state (several are described as served by `POST /check` or MCP tools). |
| A1 auth behaves as declared | pass | Every A2A probe answered HTTP 200 with no credential; `POST /sweep` without `x-sweep-token` answered `403 {"error": "forbidden"}`. |
| D1 disclosure present | pass | The card declares a provider and a compensation disclosure (`paid_by: buyer`). |

## Check it

`war_check.py` (../work-acceptance-record-cold) on `record_input.json`: signature valid, criteria hash match, criteria committed
before the check, receipt imprint match, verdict recomputed `fail`. The join to a contract is `sha256(agent-card.json)` against the
contract's `agent_card_sha256`, and this record's criteria token dated before the terms.

## What this does not establish

That the card is accurate beyond these probes; that any verdict the gate returns is correct; the operator's identity; behaviour at
other times or from other clients. The findings are a model's reading of the observation file against the committed criteria.
