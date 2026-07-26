import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPOSITORY_ROOT = resolve(ROOT, "../../..");
export const GENERATED_ROOT = join(ROOT, "web", "generated");
export const EXPECTED = Object.freeze({
  node: "v24.18.0",
  pnpm: "11.17.0",
  rust: "1.97.1",
  wasmBindgen: "0.2.126",
});

const SHARED_TOOLS = resolve(ROOT, "../toolchain-spike/.tools/bin");

export function toolPath(name) {
  const executable = process.platform === "win32" ? `${name}.exe` : name;
  return join(SHARED_TOOLS, executable);
}

function execute(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? ROOT,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = options.capture ? `\n${result.stdout ?? ""}${result.stderr ?? ""}` : "";
    throw new Error(`${command} exited with status ${result.status}${detail}`);
  }
  return result;
}

export function run(command, args, options = {}) {
  return execute(command, args, options);
}

export function capture(command, args, options = {}) {
  return execute(command, args, { ...options, capture: true }).stdout.trim();
}

export function assertOutput(command, args, expected, label) {
  const actual = capture(command, args);
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

export function pinnedRustEnvironment() {
  const rustupBin = dirname(capture("which", ["rustup"]));
  const cargoHome = resolve(process.env.CARGO_HOME ?? join(homedir(), ".cargo"));
  return {
    CARGO: capture("rustup", ["which", "--toolchain", EXPECTED.rust, "cargo"]),
    CARGO_ENCODED_RUSTFLAGS: [
      `--remap-path-prefix=${REPOSITORY_ROOT}=/wirelens`,
      `--remap-path-prefix=${cargoHome}=/cargo-home`,
    ].join("\u001f"),
    PATH: `${SHARED_TOOLS}${delimiter}${rustupBin}${delimiter}${process.env.PATH ?? ""}`,
    RUSTC: capture("rustup", ["which", "--toolchain", EXPECTED.rust, "rustc"]),
    RUSTDOC: capture("rustup", ["which", "--toolchain", EXPECTED.rust, "rustdoc"]),
    RUSTUP_TOOLCHAIN: EXPECTED.rust,
  };
}
