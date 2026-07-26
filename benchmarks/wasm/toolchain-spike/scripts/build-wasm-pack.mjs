import { mkdirSync } from "node:fs";
import { join } from "node:path";

import {
  EXPECTED,
  ROOT,
  assertOutput,
  clearGeneratedDirectory,
  pinnedRustEnvironment,
  run,
  toolPath,
} from "./tooling.mjs";

const output = join(ROOT, "web", "generated", "wasm-pack");

assertOutput(
  toolPath("wasm-pack"),
  ["--version"],
  `wasm-pack ${EXPECTED.wasmPack}`,
  "wasm-pack",
);
clearGeneratedDirectory(output);
mkdirSync(output, { recursive: true });

run(
  toolPath("wasm-pack"),
  [
    "build",
    "--mode",
    "no-install",
    "--release",
    "--no-opt",
    "--target",
    "web",
    "--out-dir",
    "web/generated/wasm-pack",
    "--out-name",
    "wirelens_wasm_probe",
    ROOT,
    "--locked",
  ],
  { env: pinnedRustEnvironment() },
);

console.log(`wasm-pack artifacts: ${output}`);
