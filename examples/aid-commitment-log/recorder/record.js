// Record every JSON-RPC response the reference resolver requests for the given anchors, with "latest" served as PIN.
// usage: node record.js <aid-clone> <out-dir> <rpc> <pin> <anchor...>
const path = require("path"), fs = require("fs");
const [AID, OUT, RPC, PIN, ...ANCH] = process.argv.slice(2);
const { ethers } = require("ethers");
const { snapshotFromChain } = require(path.join(path.resolve(AID), "tools/aid-resolve/resolve.js"));
const pinHex = "0x" + Number(PIN).toString(16);
const rec = {};
class Rec extends ethers.JsonRpcProvider {
  constructor() { super(RPC, 11155111, { staticNetwork: ethers.Network.from(11155111), batchMaxCount: 1 }); }
  async _send(payload) {
    const reqs = Array.isArray(payload) ? payload : [payload];
    const out = [];
    for (const r of reqs) {
      const fwd = JSON.parse(JSON.stringify(r.params).replace(/"latest"/g, JSON.stringify(pinHex)));
      const [res] = await super._send({ ...r, params: fwd });
      if (res.error) throw new Error(r.method + " " + JSON.stringify(res.error));
      rec[r.method + " " + JSON.stringify(r.params)] = res.result;
      out.push(res);
      await new Promise((ok) => setTimeout(ok, 250));
    }
    return out;
  }
}
(async () => {
  const p = new Rec();
  const blk = await p.send("eth_getBlockByNumber", [pinHex, false]);
  for (const a of ANCH) await snapshotFromChain(p, "0x01C05738eebD20DC80bBb9Fa1Ceb1165af8dA00F", a, null, 11921818);
  delete rec[`eth_getBlockByNumber ${JSON.stringify([pinHex, false])}`];
  fs.writeFileSync(path.join(OUT, "rpc-replay.json"), JSON.stringify({ pinnedBlock: Number(PIN), note: `latest in a key means block ${PIN}`, responses: rec }, null, 2) + "\n");
  console.log("recorded", Object.keys(rec).length, "responses; pinned block", PIN, "timestamp", Number(blk.timestamp));
})().catch((e) => { console.error(e); process.exit(1); });
