import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import {
  EXPECTED,
  GENERATED_ROOT,
  REPOSITORY_ROOT,
  assertOutput,
  pinnedRustEnvironment,
  run,
  toolPath,
} from "./tooling.mjs";

const wasmInput = join(
  REPOSITORY_ROOT,
  "target",
  "wasm32-unknown-unknown",
  "release",
  "wasm_adapter.wasm",
);

assertOutput(
  toolPath("wasm-bindgen"),
  ["--version"],
  `wasm-bindgen ${EXPECTED.wasmBindgen}`,
  "wasm-bindgen",
);

rmSync(GENERATED_ROOT, { force: true, recursive: true });
mkdirSync(GENERATED_ROOT, { recursive: true });

const environment = pinnedRustEnvironment();
run(
  environment.CARGO,
  [
    "build",
    "--locked",
    "--package",
    "wasm-adapter",
    "--release",
    "--target",
    "wasm32-unknown-unknown",
  ],
  { env: environment, cwd: REPOSITORY_ROOT },
);
run(toolPath("wasm-bindgen"), [
  "--target",
  "web",
  "--out-dir",
  GENERATED_ROOT,
  "--out-name",
  "wirelens_wasm_boundary",
  wasmInput,
]);
