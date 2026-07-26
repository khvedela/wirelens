import { readFileSync } from "node:fs";
import { join } from "node:path";

import { GENERATED_ROOT, PRODUCT_BOUNDARY_ROOT, ROOT } from "./tooling.mjs";

const protocolSources = [
  join(ROOT, "web", "boundary-client.ts"),
  join(PRODUCT_BOUNDARY_ROOT, "boundary-runtime.ts"),
  join(PRODUCT_BOUNDARY_ROOT, "packet-batch.ts"),
  join(PRODUCT_BOUNDARY_ROOT, "progress-validation.ts"),
  join(PRODUCT_BOUNDARY_ROOT, "worker-contract.ts"),
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

for (const sourcePath of protocolSources.slice(1)) {
  const source = readFileSync(sourcePath, "utf8");
  if (source.includes("benchmarks/")) {
    throw new Error(`${sourcePath} must not import benchmark-owned production code`);
  }
}

const harnessWorker = readFileSync(join(ROOT, "web", "workers", "boundary.worker.ts"), "utf8");
if (!harnessWorker.includes("installBoundaryWorker();")) {
  throw new Error("boundary harness worker must install the product-owned runtime");
}

const clientSource = readFileSync(join(ROOT, "web", "boundary-client.ts"), "utf8");
if (
  !clientSource.includes("validatePacketBatchEnvelope(transferredBytes)") ||
  clientSource.includes("validatePacketBatch(transferredBytes)")
) {
  throw new Error("main-thread packet handling must remain a fixed-envelope validation");
}

const declarations = readFileSync(join(GENERATED_ROOT, "wirelens_wasm_boundary.d.ts"), "utf8");
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
