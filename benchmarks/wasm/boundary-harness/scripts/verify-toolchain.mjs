import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { EXPECTED, REPOSITORY_ROOT, ROOT, assertOutput, toolPath } from "./tooling.mjs";

function read(path) {
  return readFileSync(path, "utf8").trim();
}

if (process.version !== EXPECTED.node) {
  throw new Error(`Node.js: expected ${EXPECTED.node}, got ${process.version}`);
}
assertOutput("corepack", ["pnpm", "--version"], EXPECTED.pnpm, "pnpm");
assertOutput(
  toolPath("wasm-bindgen"),
  ["--version"],
  `wasm-bindgen ${EXPECTED.wasmBindgen}`,
  "wasm-bindgen",
);

for (const pin of [".nvmrc", ".node-version"]) {
  if (read(resolve(REPOSITORY_ROOT, pin)) !== EXPECTED.node.slice(1)) {
    throw new Error(`${pin} does not match the harness Node.js pin`);
  }
}

const manifest = JSON.parse(read(resolve(ROOT, "package.json")));
if (manifest.packageManager !== `pnpm@${EXPECTED.pnpm}`) {
  throw new Error("packageManager does not match the harness pnpm pin");
}
for (const [dependency, version] of Object.entries({
  "@playwright/test": "1.62.0",
  "@types/node": "24.13.3",
  typescript: "6.0.3",
  vite: "8.1.5",
})) {
  if (manifest.devDependencies?.[dependency] !== version) {
    throw new Error(`${dependency} does not match the harness dependency pin`);
  }
}

console.log("boundary harness toolchain pins verified");
