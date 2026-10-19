// ots-timing fixture: B's on-chain Document (as recorded at the pinned block) reduced to facet 1 alone, so its OTS proof is the one judged.
const path = require("path"), fs = require("fs");
const [AID, B] = process.argv.slice(2);
const { ethers } = require("ethers");
const { canonicalize } = require(path.join(path.resolve(AID), "tools/jcs"));
const rec = JSON.parse(fs.readFileSync(path.join(B, "resolved-B.json")));
const M = JSON.parse(fs.readFileSync(path.join(B, "manifest.json")));
const doc = JSON.parse(JSON.stringify(rec.snapshot.document));
const ft = "aid:behavior/verification-verdict/v1";
const mine = doc.facets.filter((f) => f.facetType === ft);
const f1 = mine.find((f) => !f.supersedes);
if (mine.length !== 2 || !f1) throw new Error("expected the two issuer facets");
doc.facets = [f1];
const fx = { note: "B's Document as read at block " + M.workedExample.pinnedBlock + " with only the first issuer facet kept (its successor removed), so the check judges facet 1's own OpenTimestamps proof; in the full Document the facet is history, see resolved-B.json",
  document: doc, documentDigest: ethers.keccak256(ethers.toUtf8Bytes(canonicalize(doc))), now: M.workedExample.pinnedBlockTimestamp, mutate: ft,
  expect: { [ft]: { timing: "pre-outcome" } } };
fs.writeFileSync(path.join(B, "ots-fixture.json"), JSON.stringify(fx, null, 2) + "\n");
console.log("fixture written; facet 1 digest", f1.digest, "digestAlg", f1.digestAlg);
