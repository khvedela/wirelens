import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

import { ROOT, sha256 } from "./tooling.mjs";

const outputName = "wirelens_wasm_probe";
const variants = ["direct", "wasm-pack"];
const report = { bundles: {}, dist: {} };
const expectedArtifacts = Object.freeze({
  jsBytes: 4_411,
  jsSha256: "57738e48798b60a3d9ae9abf0ffdc5ff75678b38a65a10c8d2d17e122d5d7093",
  wasmBytes: 14_709,
  wasmSha256: "7b2965e3e649d1ca85eb7dbbc2fe66df3794da4fea91f810a146023a01ffb08e",
});

function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

for (const variant of variants) {
  const directory = join(ROOT, "web", "generated", variant);
  const js = join(directory, `${outputName}.js`);
  const wasm = join(directory, `${outputName}_bg.wasm`);
  const declaration = join(directory, `${outputName}.d.ts`);
  for (const required of [js, wasm, declaration]) {
    if (!statSync(required).isFile()) {
      throw new Error(`missing ${relative(ROOT, required)}`);
    }
  }

  const bytes = readFileSync(wasm);
  if (!bytes.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d]))) {
    throw new Error(`${variant} output does not have the WebAssembly magic header`);
  }
  const module = await WebAssembly.compile(bytes);
  const exports = WebAssembly.Module.exports(module).map(({ name }) => name);
  for (const expected of ["byte_sum", "probe_schema_version"]) {
    if (!exports.includes(expected)) {
      throw new Error(`${variant} output is missing the ${expected} export`);
    }
  }
  const bundle = {
    exports: exports.filter((name) => !name.startsWith("__wbindgen")),
    jsBytes: statSync(js).size,
    jsSha256: sha256(js),
    wasmBytes: bytes.byteLength,
    wasmSha256: sha256(wasm),
  };
  for (const [measurement, expected] of Object.entries(expectedArtifacts)) {
    if (bundle[measurement] !== expected) {
      throw new Error(
        `${variant} ${measurement}: expected ${expected}, got ${bundle[measurement]}`,
      );
    }
  }
  report.bundles[variant] = bundle;
}

if (report.bundles.direct.wasmSha256 !== report.bundles["wasm-pack"].wasmSha256) {
  throw new Error("direct and wasm-pack Wasm outputs are not byte-identical");
}
if (report.bundles.direct.jsSha256 !== report.bundles["wasm-pack"].jsSha256) {
  throw new Error("direct and wasm-pack JavaScript bindings are not byte-identical");
}

const dist = join(ROOT, "dist");
const distFiles = walk(dist);
const distWasm = distFiles.filter((path) => path.endsWith(".wasm"));
if (distWasm.length !== 1) {
  throw new Error(`production bundle must contain exactly one Wasm asset, got ${distWasm.length}`);
}
if (
  statSync(distWasm[0]).size !== expectedArtifacts.wasmBytes
  || sha256(distWasm[0]) !== expectedArtifacts.wasmSha256
) {
  throw new Error("production Wasm asset does not match the recorded reproducible artifact");
}

const inspectableExtensions = new Set([".css", ".html", ".js", ".json"]);
const remoteReferences = [];
const executableRemotePatterns = [
  /\bfetch\(\s*["'`]https?:\/\//u,
  /\bimportScripts\(\s*["'`]https?:\/\//u,
  /\bimport\(\s*["'`]https?:\/\//u,
  /\b(?:src|href)=["']https?:\/\//u,
  /\bnew\s+(?:SharedWorker|Worker)\(\s*["'`]https?:\/\//u,
];
for (const path of distFiles) {
  const extension = path.slice(path.lastIndexOf("."));
  const source = inspectableExtensions.has(extension) ? readFileSync(path, "utf8") : "";
  if (executableRemotePatterns.some((pattern) => pattern.test(source))) {
    remoteReferences.push(relative(dist, path));
  }
}
if (remoteReferences.length > 0) {
  throw new Error(`production assets contain executable remote references: ${remoteReferences.join(", ")}`);
}

report.dist = {
  fileCount: distFiles.length,
  files: distFiles.map((path) => ({
    bytes: statSync(path).size,
    path: relative(dist, path),
  })),
  remoteExecutableReferences: 0,
};

console.log(JSON.stringify(report, null, 2));
