import { existsSync } from "node:fs";

import {
  EXPECTED,
  TOOLS_ROOT,
  assertOutput,
  pinnedRustEnvironment,
  run,
  toolPath,
} from "./tooling.mjs";

const environment = pinnedRustEnvironment();

const tools = [
  {
    binary: "wasm-bindgen",
    crate: "wasm-bindgen-cli",
    expectedOutput: `wasm-bindgen ${EXPECTED.wasmBindgen}`,
    version: EXPECTED.wasmBindgen,
  },
  {
    binary: "wasm-pack",
    crate: "wasm-pack",
    expectedOutput: `wasm-pack ${EXPECTED.wasmPack}`,
    version: EXPECTED.wasmPack,
  },
];

for (const tool of tools) {
  const binary = toolPath(tool.binary);
  let installed = false;
  if (existsSync(binary)) {
    try {
      assertOutput(binary, ["--version"], tool.expectedOutput, tool.binary);
      installed = true;
    } catch {
      installed = false;
    }
  }

  if (!installed) {
    run(environment.CARGO, [
      "install",
      "--locked",
      "--force",
      "--root",
      TOOLS_ROOT,
      "--version",
      `=${tool.version}`,
      tool.crate,
    ], { env: environment });
  }
  assertOutput(binary, ["--version"], tool.expectedOutput, tool.binary);
}

console.log("Pinned Wasm tools are installed under .tools/bin.");
