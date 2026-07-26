# Wasm toolchain spike evidence

## Environment

- Date: 2026-07-26
- Branch: `feature/rust-wasm-toolchain`
- Local OS: macOS 26.6, Apple Silicon
- Reference hardware: Apple M3 Pro MacBook Pro, 11 cores, 18 GB memory
- Clean environment: pending the scoped `Toolchain spike` Ubuntu 24.04 GitHub Actions run; its passing URL will replace this note before merge
- Probe data: the in-memory synthetic vector `[1, 2, 3, 4, 255]`; no capture file is read or committed

## Commands and results

| Command | Result | Evidence |
| --- | --- | --- |
| `corepack pnpm install --frozen-lockfile` | Pass | Exact pnpm and package lock accepted |
| `corepack pnpm run tools:install` | Pass | Local `wasm-bindgen` 0.2.126 and `wasm-pack` 0.15.0 installed |
| `corepack pnpm run verify:toolchain` | Pass | Exact Rust, Cargo, Node, pnpm, Wasm CLIs, and Wasm target verified |
| `corepack pnpm run check:rust` | Pass | Rustfmt and Clippy with warnings denied |
| `corepack pnpm run test:rust` | Pass | 2 unit tests and doc tests passed |
| `corepack pnpm run build:direct` | Pass | Cargo release build plus direct `wasm-bindgen --target web` |
| `corepack pnpm run build:wasm-pack` | Pass with documented `--no-opt` | `wasm-pack --target web` produced the comparison package |
| `corepack pnpm run typecheck` | Pass | TypeScript 6.0.3 strict check passed |
| `corepack pnpm run build:web` | Pass | Static production React/Vite bundle emitted |
| `corepack pnpm run verify:artifacts` | Pass | Exports, hashes, sizes, Wasm magic, static asset, and remote executable references checked |
| `corepack pnpm run test:browser:direct` | Pass | Chromium and Firefox |
| `corepack pnpm run test:browser:wasm-pack` | Pass | Chromium and Firefox |
| `corepack pnpm run verify:all` | Pass | Full sequence repeated end-to-end |

The first default wasm-pack release attempt failed because its downloaded `wasm-opt` rejected bulk-memory operations in Rust 1.97.1 output. The committed comparison script makes this behavior explicit by passing `--no-opt`; `--mode no-install` also prevents hidden tool acquisition. The direct flow needed no workaround.

## Verified versions

```json
{
  "cargo": "cargo 1.97.1 (c980f4866 2026-06-30)",
  "node": "24.18.0",
  "pnpm": "11.17.0",
  "rustc": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
  "wasmBindgen": "wasm-bindgen 0.2.126",
  "wasmPack": "wasm-pack 0.15.0",
  "target": "wasm32-unknown-unknown"
}
```

## Artifact comparison

| Artifact | Direct | wasm-pack |
| --- | ---: | ---: |
| Generated binding JavaScript | 4,411 bytes | 4,411 bytes |
| Binding JavaScript SHA-256 | `57738e48798b60a3d9ae9abf0ffdc5ff75678b38a65a10c8d2d17e122d5d7093` | Same |
| Processed Wasm | 14,709 bytes | 14,709 bytes |
| Wasm SHA-256 | `7b2965e3e649d1ca85eb7dbbc2fe66df3794da4fea91f810a146023a01ffb08e` | Same |
| Production worker chunk | 2,333 bytes | 2,336 bytes |

The initial Ubuntu 24.04 x64 run exposed absolute Cargo registry paths in panic-location strings. The committed `CARGO_ENCODED_RUSTFLAGS` remap both the checkout and Cargo home to stable virtual roots before compilation; the verifier now requires macOS arm64 and Ubuntu x64 to produce the single recorded JavaScript and Wasm hashes above.

The shared production build also emitted one 14,709-byte fingerprinted Wasm asset and a 192,855-byte React entry chunk. These are toolchain comparison measurements, not product bundle or performance budgets.

## Browser assertions

For both direct and wasm-pack variants in Chromium and Firefox:

- an ECMAScript module worker loaded the generated binding;
- Rust returned byte sum `265` and schema version `1`;
- the main-thread input buffer was detached by transfer;
- exactly one same-origin `.wasm` request occurred;
- every non-loopback request was intercepted and blocked;
- observed external runtime requests were zero; and
- page exceptions and console errors were zero.

## Recommendation input

The direct flow is selected because Cargo and binding generation remain explicit, it avoids package-publishing metadata, and it does not depend on wasm-pack's downloaded optimizer. wasm-pack remains a reproducibly measured alternative, not the product build orchestrator.

This probe does not establish capture throughput, worker cancellation latency, Wasm-boundary copy cost, product memory use, post-load PWA caching, or parser correctness. Those remain implementation evidence for issues #9, #10, and later hardening work.
