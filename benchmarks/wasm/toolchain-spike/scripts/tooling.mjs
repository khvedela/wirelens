import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { delimiter, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const TOOLS_ROOT = join(ROOT, ".tools");
export const EXPECTED = Object.freeze({
  cargo: "1.97.1",
  frontend: Object.freeze({
    "@playwright/test": "1.62.0",
    "@types/react": "19.2.17",
    "@types/react-dom": "19.2.3",
    "@vitejs/plugin-react": "6.0.4",
    react: "19.2.8",
    "react-dom": "19.2.8",
    typescript: "6.0.3",
    vite: "8.1.5",
  }),
  node: "24.18.0",
  pnpm: "11.17.0",
  rust: "1.97.1",
  wasmBindgen: "0.2.126",
  wasmPack: "0.15.0",
});

export function toolPath(name) {
  const executable = process.platform === "win32" ? `${name}.exe` : name;
  return join(TOOLS_ROOT, "bin", executable);
}

function execute(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
    stdio: options.capture ? "pipe" : "inherit",
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const detail = options.capture
      ? `\n${result.stdout ?? ""}${result.stderr ?? ""}`
      : "";
    throw new Error(`${command} exited with status ${result.status}${detail}`);
  }
  return result;
}

export function run(command, args, options = {}) {
  execute(command, args, options);
}

export function capture(command, args, options = {}) {
  return execute(command, args, { ...options, capture: true }).stdout.trim();
}

export function assertOutput(command, args, expected, label) {
  const actual = capture(command, args);
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
  return actual;
}

export function pinnedRustEnvironment() {
  const rustupBin = dirname(capture("which", ["rustup"]));
  const localToolsBin = join(TOOLS_ROOT, "bin");
  return {
    CARGO: capture("rustup", ["which", "--toolchain", EXPECTED.rust, "cargo"]),
    PATH: `${localToolsBin}${delimiter}${rustupBin}${delimiter}${process.env.PATH ?? ""}`,
    RUSTC: capture("rustup", ["which", "--toolchain", EXPECTED.rust, "rustc"]),
    RUSTDOC: capture("rustup", ["which", "--toolchain", EXPECTED.rust, "rustdoc"]),
    RUSTUP_TOOLCHAIN: EXPECTED.rust,
  };
}

export function clearGeneratedDirectory(directory) {
  const resolved = resolve(directory);
  const generatedRoot = resolve(ROOT, "web", "generated") + sep;
  if (!resolved.startsWith(generatedRoot)) {
    throw new Error(`refusing to clear non-generated path: ${resolved}`);
  }
  rmSync(resolved, { force: true, recursive: true });
}

export function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
