import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  EXPECTED,
  ROOT,
  assertOutput,
  capture,
  pinnedRustEnvironment,
  toolPath,
} from "./tooling.mjs";

const repositoryRoot = resolve(ROOT, "../../..");

function read(path) {
  return readFileSync(path, "utf8");
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertContains(source, expected, label) {
  if (!source.includes(expected)) {
    throw new Error(`${label}: missing ${JSON.stringify(expected)}`);
  }
}

for (const directory of [repositoryRoot, ROOT]) {
  const label = directory === repositoryRoot ? "repository" : "probe";
  assertEqual(read(resolve(directory, ".nvmrc")).trim(), EXPECTED.node, `${label} .nvmrc`);
  assertEqual(
    read(resolve(directory, ".node-version")).trim(),
    EXPECTED.node,
    `${label} .node-version`,
  );
  const rustToolchain = read(resolve(directory, "rust-toolchain.toml"));
  for (const expected of [
    `channel = "${EXPECTED.rust}"`,
    'components = ["clippy", "rustfmt"]',
    'profile = "minimal"',
    'targets = ["wasm32-unknown-unknown"]',
  ]) {
    assertContains(rustToolchain, expected, `${label} Rust toolchain pin`);
  }
}

const packageManifest = JSON.parse(read(resolve(ROOT, "package.json")));
assertEqual(packageManifest.packageManager, `pnpm@${EXPECTED.pnpm}`, "packageManager pin");
assertEqual(packageManifest.engines?.node, EXPECTED.node, "Node engine pin");
assertEqual(packageManifest.engines?.pnpm, EXPECTED.pnpm, "pnpm engine pin");
for (const [dependency, expected] of Object.entries(EXPECTED.frontend)) {
  const actual = packageManifest.dependencies?.[dependency]
    ?? packageManifest.devDependencies?.[dependency];
  assertEqual(actual, expected, `${dependency} package pin`);
}

const cargoManifest = read(resolve(ROOT, "Cargo.toml"));
assertContains(
  cargoManifest,
  `rust-version = "${EXPECTED.rust}"`,
  "probe Cargo Rust version",
);
assertContains(
  cargoManifest,
  `wasm-bindgen = "=${EXPECTED.wasmBindgen}"`,
  "wasm-bindgen crate pin",
);

const workflow = read(resolve(repositoryRoot, ".github/workflows/toolchain-spike.yml"));
assertContains(workflow, `pnpm@${EXPECTED.pnpm} --activate`, "workflow pnpm pin");
assertContains(
  workflow,
  `rustup toolchain install ${EXPECTED.rust}`,
  "workflow Rust toolchain pin",
);

if (process.versions.node !== EXPECTED.node) {
  throw new Error(`Node.js: expected ${EXPECTED.node}, got ${process.versions.node}`);
}

const environment = pinnedRustEnvironment();
const versions = {
  cargo: capture(environment.CARGO, ["--version"], { env: environment }),
  node: process.versions.node,
  pnpm: assertOutput("corepack", ["pnpm", "--version"], EXPECTED.pnpm, "pnpm"),
  rustc: capture(environment.RUSTC, ["--version"], { env: environment }),
  wasmBindgen: assertOutput(
    toolPath("wasm-bindgen"),
    ["--version"],
    `wasm-bindgen ${EXPECTED.wasmBindgen}`,
    "wasm-bindgen",
  ),
  wasmPack: assertOutput(
    toolPath("wasm-pack"),
    ["--version"],
    `wasm-pack ${EXPECTED.wasmPack}`,
    "wasm-pack",
  ),
};

if (!versions.rustc.startsWith(`rustc ${EXPECTED.rust} `)) {
  throw new Error(`rustc: expected ${EXPECTED.rust}, got ${versions.rustc}`);
}
if (!versions.cargo.startsWith(`cargo ${EXPECTED.cargo} `)) {
  throw new Error(`cargo: expected ${EXPECTED.cargo}, got ${versions.cargo}`);
}

const targets = capture("rustup", [
  "target",
  "list",
  "--installed",
  "--toolchain",
  EXPECTED.rust,
]);
if (!targets.split("\n").includes("wasm32-unknown-unknown")) {
  throw new Error(`wasm32-unknown-unknown is not installed for Rust ${EXPECTED.rust}`);
}

console.log(JSON.stringify({ ...versions, target: "wasm32-unknown-unknown" }, null, 2));
