# Recorder for the ERC-8434 recorded case

These scripts produce `examples/sepolia-commitment-log/` in [aid-standard](https://github.com/garyyang-finchip/aid-standard). They run against a clone of aid-standard with `ethers` 6 on `NODE_PATH`.

```
node record.js <aid-standard> <out> <archive sepolia rpc> 11944211 0xd6b24DF77E6f5e7BEFf51460a1d60C2fb7ac9eb2 0x4AA351E5f00eBe168E5C6f823f2940553d164991
#  then write <out>/manifest.json (issuerLogs from ../aid-document.json, logEntries from ../log.json)
node gen.js <aid-standard> <out>/manifest.json      # resolved-B.json, resolved-issuer.json
node fixture.js <aid-standard> <out>                # ots-fixture.json (facet 1 alone; then add aid, issuerLogs, logEntries through entry 1)
```

- `record.js` forwards each JSON-RPC request with `latest` replaced by the pinned block. It stores the response under the request as the resolver made it.
- `gen.js` computes the resolved files the way `scripts/sepolia-replay.js` does.
- The RPC must serve historical state. Pruned public nodes refuse `eth_call` at an older block.
