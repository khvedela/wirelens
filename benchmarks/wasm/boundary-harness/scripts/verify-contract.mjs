import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ROOT } from "./tooling.mjs";

const protocolSources = [
  join(ROOT, "web", "boundary-client.ts"),
  join(ROOT, "web", "worker-contract.ts"),
  join(ROOT, "web", "workers", "boundary.worker.ts"),
];
const forbidden = ["JSON.stringify", "FileReader", "readAsText", "TextDecoder"];

for (const sourcePath of protocolSources) {
  const source = readFileSync(sourcePath, "utf8");
  for (const token of forbidden) {
    if (source.includes(token)) {
      throw new Error(`${sourcePath} uses forbidden whole-capture text/JSON primitive ${token}`);
    }
  }
}

const clientSource = readFileSync(join(ROOT, "web", "boundary-client.ts"), "utf8");
if (
  !clientSource.includes("validatePacketBatchEnvelope(transferredBytes)") ||
  clientSource.includes("validatePacketBatch(transferredBytes)")
) {
  throw new Error("main-thread packet handling must remain a fixed-envelope validation");
}

const declarations = readFileSync(
  join(ROOT, "web", "generated", "wirelens_wasm_boundary.d.ts"),
  "utf8",
);
const apiSnapshot = readFileSync(join(ROOT, "API.md"), "utf8");
const snapshotMatch = apiSnapshot.match(
  /<!-- generated-signatures:start -->\s*```ts\s*([\s\S]*?)\s*```\s*<!-- generated-signatures:end -->/,
);
if (!snapshotMatch) {
  throw new Error("API.md is missing its generated-signatures snapshot");
}
const expectedSignatures = snapshotMatch[1]
  .split("\n")
  .map((signature) => signature.trim())
  .filter(Boolean);
if (new Set(expectedSignatures).size !== expectedSignatures.length) {
  throw new Error("API.md contains duplicate generated signatures");
}
for (const signature of expectedSignatures) {
  if (!declarations.includes(signature)) {
    throw new Error(`generated Wasm declaration drifted from API.md: ${signature}`);
  }
}

console.log(
  "boundary transport is binary-only and generated declarations match the reviewed API snapshot",
);
