import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const sourceRoots = [
  "Cargo.lock",
  "Cargo.toml",
  "rust-toolchain.toml",
  "apps/web",
  "crates/packet-core",
  "crates/wasm-adapter",
  "benchmarks/wasm/boundary-harness/API.md",
  "benchmarks/wasm/boundary-harness/scripts",
];
const ignoredDirectories = new Set(["dist", "generated", "node_modules", "test-results"]);

export async function sourceTreeIdentity() {
  const paths = [];
  const visit = async (absolutePath) => {
    const metadata = await stat(absolutePath);
    if (!metadata.isDirectory()) {
      paths.push(absolutePath);
      return;
    }
    for (const entry of (await readdir(absolutePath)).sort()) {
      if (ignoredDirectories.has(entry)) continue;
      await visit(join(absolutePath, entry));
    }
  };
  for (const root of sourceRoots) await visit(join(repositoryRoot, root));
  paths.sort((left, right) => left.localeCompare(right));

  const digest = createHash("sha256");
  for (const path of paths) {
    digest.update(relative(repositoryRoot, path));
    digest.update("\0");
    digest.update(await readFile(path));
    digest.update("\0");
  }
  return {
    baseRevision: execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repositoryRoot,
      encoding: "utf8",
    }).trim(),
    sha256: digest.digest("hex"),
  };
}
