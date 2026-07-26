# Contributing to WireLens

Thank you for helping build a privacy-first network investigation tool. WireLens is under active implementation; work must follow the accepted architecture decisions and the dependency state recorded on its issue.

## Before you start

1. Read the [product vision](docs/product/product-vision.md), [accepted architecture decisions](docs/architecture/README.md), [roadmap](docs/roadmap.md), and [agent guidance](AGENTS.md).
2. Search existing issues and discuss substantial scope or boundary changes before writing code.
3. Work from an issue with clear acceptance criteria. Keep pull requests focused and link the issue.

## Development principles

- Preserve local processing: offline captures must not be uploaded.
- Treat captures and decoded values as untrusted and potentially sensitive.
- Keep parsing and analysis independent of UI and browser frameworks.
- Prefer synthetic or explicitly redistributable packet fixtures with documented provenance.
- Add correctness tests for parsing changes and benchmarks for performance-sensitive changes.
- Keep browser analysis off the main thread and avoid unnecessary packet-buffer copies.

## Supported toolchains

The repository pins Rust `1.97.1` in [`rust-toolchain.toml`](rust-toolchain.toml) and Node.js `24.18.0` in both [`.nvmrc`](.nvmrc) and [`.node-version`](.node-version). Rust crates retain the workspace minimum supported Rust version (MSRV) of `1.85` unless an accepted decision changes it.

Use the `rustup` shims before any Homebrew Rust installation so the repository pin and Wasm target take effect. Verify a new shell before building:

```sh
which rustc
rustc --version
cargo --version
rustup show active-toolchain
node --version
corepack --version
```

The expected Rust and Node versions are the pinned values above. The toolchain file installs `rustfmt`, Clippy, and `wasm32-unknown-unknown`. Enable Corepack and use the package manager version declared by the package being built; do not substitute an unpinned global installation.

Run the core Rust gates from the repository root:

```sh
cargo fmt --all --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo check --locked --workspace --target wasm32-unknown-unknown --all-features
```

MSRV validation is a separate compatibility gate:

```sh
rustup toolchain install 1.85.0 --profile minimal
RUSTUP_TOOLCHAIN=1.85.0 cargo check --locked --workspace --all-targets --all-features
```

The disposable worker/Wasm build experiment and its exact CLI pins are documented in [`benchmarks/wasm/toolchain-spike`](benchmarks/wasm/toolchain-spike). It is deliberately excluded from the product Cargo workspace.

Changes to capture import, the Wasm adapter, or the worker protocol must also run the production boundary harness:

```sh
nvm use
cd benchmarks/wasm/boundary-harness
corepack pnpm install --frozen-lockfile
corepack pnpm run tools:install
corepack pnpm verify
corepack pnpm evidence
```

`verify` builds the product Wasm with direct Cargo plus the exact pinned `wasm-bindgen`, validates the binary-only transport contract, builds the production module worker, and runs the behavioral suite in Chromium and Firefox. `evidence` regenerates the committed [boundary measurements](benchmarks/wasm/boundary-harness/EVIDENCE.md) from synthetic in-memory fixtures; never substitute a private capture.

Parser robustness changes must run the deterministic property suite and replay the committed synthetic fuzz corpus:

```sh
cargo test --locked -p packet-core --test import_properties
FUZZ_NIGHTLY=nightly-2026-07-20
rustup toolchain install "$FUZZ_NIGHTLY" --profile minimal
cargo +"$FUZZ_NIGHTLY" install cargo-fuzz --version 0.13.2 --locked
for target in capture_import protocol_decode network_decode; do
  for seed in "fuzz/corpus/$target"/*; do
    cargo +"$FUZZ_NIGHTLY" fuzz run "$target" "$seed" -- -runs=1 -timeout=2 -rss_limit_mb=1024
  done
done
```

The weekly workflow uses the same pinned fuzz toolchain for bounded importer, whole-capture decoder,
and focused network-decoder mutation campaigns. Local longer runs use the matching target and corpus;
the focused target's extra selector byte makes its libFuzzer input limit 4,097 bytes:

```sh
cargo +"$FUZZ_NIGHTLY" fuzz run protocol_decode fuzz/corpus/protocol_decode -- -max_total_time=600 -max_len=4096 -timeout=2 -rss_limit_mb=1024
cargo +"$FUZZ_NIGHTLY" fuzz run network_decode fuzz/corpus/network_decode -- -max_total_time=600 -max_len=4097 -timeout=2 -rss_limit_mb=1024
```

Keep corpus additions small and synthetic, and record their provenance and intent in
[`fixtures/manifests`](fixtures/manifests).

## Changes and review

Use Conventional Commit-style messages where practical. Before requesting review, run the formatting, linting, tests, security checks, and builds defined by the repository at that time. Explain performance and privacy/security impact in the pull-request template. Do not include credentials, private captures, or generated dependency directories.

## Reporting security issues

Do not open a public issue for a vulnerability or attach a sensitive capture. Follow [SECURITY.md](SECURITY.md).
