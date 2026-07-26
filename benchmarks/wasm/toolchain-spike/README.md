# Rust/Wasm browser toolchain spike

This disposable probe compares a direct `wasm-bindgen` build with `wasm-pack`, then feeds both outputs through the same production React, Vite, and TypeScript module-worker integration. It is deliberately isolated from the product workspace and does not choose or implement a product API.

The probe uses only the in-memory synthetic byte vector `[1, 2, 3, 4, 255]`. It never reads a packet capture, persists input, or contacts an external service at runtime.

## Pinned toolchain

| Tool | Version |
| --- | --- |
| Rust / Cargo | 1.97.1 |
| `wasm32-unknown-unknown` | Rust 1.97.1 component |
| `wasm-bindgen` crate and CLI | 0.2.126 |
| `wasm-pack` | 0.15.0 |
| Node.js | 24.18.0 |
| pnpm | 11.17.0 |
| Vite | 8.1.5 |
| React / React DOM | 19.2.8 |
| TypeScript | 6.0.3 |
| Playwright | 1.62.0 |

The local CLIs are installed under ignored `.tools/`; the scripts reject mismatched versions. The Rust and pnpm dependency graphs are committed as lockfiles. Encoded Rust flags remap the checkout and Cargo-home paths before compilation so panic-location strings do not make Wasm artifacts host-path-dependent; the verifier requires both build flows and both measured hosts to remain byte-identical.

## Reproduce

From this directory:

```sh
nvm install
nvm use
node --version # must print v24.18.0
corepack pnpm install --frozen-lockfile
corepack pnpm run tools:install
corepack pnpm exec playwright install chromium firefox
corepack pnpm test
```

The first two commands use `nvm`; an equivalent version manager is fine, but it must activate the exact Node version in `.nvmrc`/`.node-version` before Corepack runs.

`pnpm test` (`verify:all`) checks Rust formatting and Clippy, runs Rust unit tests, checks every pinned tool, builds both Wasm variants, type-checks and bundles the production React frontend, validates the generated artifacts, and runs both variants in Chromium and Firefox.

Individual build paths are available for comparison:

```sh
corepack pnpm run build:direct
corepack pnpm run build:wasm-pack
corepack pnpm run build:web
corepack pnpm run verify:artifacts
```

The direct path runs Cargo followed by the exact local `wasm-bindgen` CLI. The `wasm-pack` path runs the exact local `wasm-pack`, with Cargo and Rustc forced to the pinned Rust toolchain. It uses `--mode no-install` so wasm-pack cannot acquire an unverified binding generator, and passes `--no-opt` because wasm-pack 0.15.0's downloaded `wasm-opt` build rejected the bulk-memory instructions emitted by Rust 1.97.1; that observed failure is part of the comparison evidence. Generated bindings, build output, installed tools, and browser reports are ignored.

## What the browser test proves

For each build path, Playwright verifies that:

- Vite's production output starts an ECMAScript module worker;
- that worker initializes the generated Wasm module and calls two Rust exports;
- the main thread transfers, rather than clones, the synthetic input buffer;
- the result is returned to the page; and
- every observed runtime resource/request is local to the preview origin (zero external runtime requests).

This is toolchain evidence only. It does not establish capture-import throughput, memory limits, cancellation latency, or product parser correctness.

Use [EVIDENCE.md](./EVIDENCE.md) when recording a run for an architecture decision or pull request.
