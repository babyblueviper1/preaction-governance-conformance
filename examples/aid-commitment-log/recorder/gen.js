// Produce resolved-<name>.json exactly as scripts/sepolia-replay.js computes them (same snapshot/ctx/verifier path), for the first recording.
const path = require("path"), fs = require("fs");
const [AID, MAN] = process.argv.slice(2);
const { ethers } = require("ethers");
const { snapshotFromChain, resolveSnapshot } = require(path.join(path.resolve(AID), "tools/aid-resolve/resolve.js"));
const DEP = JSON.parse(fs.readFileSync(MAN)); const B = path.dirname(MAN);
const R = JSON.parse(fs.readFileSync(path.join(B, "rpc-replay.json"))).responses;
class P extends ethers.JsonRpcProvider { constructor() { super("http://replay.invalid", DEP.chainId, { staticNetwork: ethers.Network.from(DEP.chainId), batchMaxCount: 1 }); }
  async _send(pl) { return (Array.isArray(pl) ? pl : [pl]).map((r) => { const k = r.method + " " + JSON.stringify(r.params); if (!(k in R)) throw new Error("not recorded " + k); return { id: r.id, jsonrpc: "2.0", result: R[k] }; }); } }
(async () => {
  const provider = new P(); const we = DEP.workedExample; const ctx = { provider };
  for (const v of DEP.verifiers || []) { const mod = require(path.join(path.resolve(AID), "tools", "aid-resolve", "verifiers", v + ".js")); ctx.verifiers = { ...(ctx.verifiers || {}), [v]: mod["verify" + v[0].toUpperCase() + v.slice(1)] || mod.verify || mod.default }; }
  for (const [name, anchor] of Object.entries(we.anchors)) {
    const snapshot = await snapshotFromChain(provider, DEP.contracts.AIDRegistry.address, anchor, null, DEP.contracts.AIDRegistry.block);
    for (const k of DEP.ctx || []) if (snapshot[k] === undefined && we[k] !== undefined) snapshot[k] = we[k];
    for (const k of ["trustedTimestamps", "issuerLogs", "logEntries", "linkedDocuments"]) if (snapshot[k] !== undefined) ctx[k] = snapshot[k];
    const resolved = await resolveSnapshot(snapshot, we.pinnedBlockTimestamp, ctx);
    fs.writeFileSync(path.join(B, `resolved-${name}.json`), JSON.stringify({ snapshot, resolved }, null, 2) + "\n");
    console.log(name, resolved.onChainState, "current", resolved.facets.current.map((f) => [f.facetType, f.timing, f.exclusivity]), "history", resolved.facets.history.map((f) => [f.facetType, f.timing, f.reason, f.supersessionTiming, f.reversedAfterOutcome]));
  }
})().catch((e) => { console.error(e); process.exit(1); });
