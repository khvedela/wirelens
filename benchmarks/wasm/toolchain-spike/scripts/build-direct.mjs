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

const output = join(ROOT, "web", "generated", "direct");
const input = join(
  ROOT,
  "target",
  "wasm32-unknown-unknown",
  "release",
  "wirelens_wasm_toolchain_spike.wasm",
);

assertOutput(
  toolPath("wasm-bindgen"),
  ["--version"],
  `wasm-bindgen ${EXPECTED.wasmBindgen}`,
  "wasm-bindgen",
);
clearGeneratedDirectory(output);
mkdirSync(output, { recursive: true });

const environment = pinnedRustEnvironment();
run(environment.CARGO, [
  "build",
  "--locked",
  "--release",
  "--target",
  "wasm32-unknown-unknown",
], { env: environment });
run(toolPath("wasm-bindgen"), [
  "--target",
  "web",
  "--out-dir",
  output,
  "--out-name",
  "wirelens_wasm_probe",
  input,
]);

console.log(`Direct wasm-bindgen artifacts: ${output}`);
