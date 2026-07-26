# ADR-0006: Rust, WebAssembly, and frontend toolchain

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#3](https://github.com/khvedela/wirelens/issues/3)
- **Parent epic:** [#1](https://github.com/khvedela/wirelens/issues/1)

## Context

WireLens needs a reproducible way to compile Rust to `wasm32-unknown-unknown`, generate JavaScript bindings, load them only inside an ECMAScript-module Web Worker, and emit a static production frontend. The application must not fetch code or Wasm from external origins, CDNs, or registries at runtime, and the choice must keep Rust/JavaScript binding versions explicit.

This decision validates tooling only. The disposable probe sums a small synthetic byte vector and contains no capture parsing, product API, telemetry, or packet data.

## Experiment

The reproducible probe is under [`benchmarks/wasm/toolchain-spike`](../../benchmarks/wasm/toolchain-spike). The same Rust crate and Vite module-worker frontend are built through two viable flows:

1. `cargo build --release --target wasm32-unknown-unknown`, followed by the exact-version `wasm-bindgen --target web` CLI;
2. `wasm-pack build --release --target web`, with its generated package consumed by the same frontend contract.

Each flow must:

- produce a static Vite production build;
- emit a separate worker chunk and fingerprinted Wasm asset;
- initialize Wasm from the module worker and return the deterministic result `265`;
- pass browser tests against the production server;
- make zero non-loopback runtime requests;
- record generated artifact sizes, hashes, versions, and commands.

## Supported versions

| Component | Supported pin | Role |
| --- | --- | --- |
| Rust | `1.97.1` | Contributor and CI build toolchain |
| Workspace Rust MSRV | `1.85` | Platform-neutral crate compatibility gate |
| Rust target | `wasm32-unknown-unknown` | Browser Wasm compilation |
| Node.js | `24.18.0` LTS | Frontend and build-script runtime |
| pnpm | `11.17.0` | Locked frontend dependency installation through Corepack |
| `wasm-bindgen` crate and CLI | `0.2.126` | Binding schema and direct generator |
| `wasm-pack` | `0.15.0` | Measured comparison flow only |
| Vite / React / TypeScript | `8.1.5` / `19.2.8` / `6.0.3` | Product application, bundle, and type checking |
| Playwright | `1.62.0` | Chromium and Firefox production-bundle validation |
| Biome | `2.5.5` | Product TypeScript/JavaScript/CSS formatting and linting |

The repository pins Rust in [`rust-toolchain.toml`](../../rust-toolchain.toml) and Node in [`.nvmrc`](../../.nvmrc) and [`.node-version`](../../.node-version). Each frontend package pins pnpm and every JavaScript dependency in its lockfile. The `wasm-bindgen` crate and CLI must remain the exact same version because their generated binding schema is version-sensitive.

TypeScript 7 is intentionally not the product baseline: its stable release removed the programmatic API used by parts of the wider TypeScript tooling ecosystem. The Vite probe uses the conservative 6.0 line until downstream tools explicitly validate TypeScript 7 support.

Version pins were verified against the official [Rust 1.97.1 release](https://blog.rust-lang.org/releases/1.97.1/), [Node.js 24.18.0 release](https://nodejs.org/en/blog/release/v24.18.0), [wasm-bindgen 0.2.126 release](https://github.com/wasm-bindgen/wasm-bindgen/releases/tag/0.2.126), [wasm-pack 0.15.0 release](https://github.com/wasm-bindgen/wasm-pack/releases/tag/v0.15.0), [Vite worker and asset behavior](https://vite.dev/guide/features.html), and the [TypeScript 7 compatibility announcement](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/).

## Results

Measured results are generated from committed scripts and recorded in the probe's [`EVIDENCE.md`](../../benchmarks/wasm/toolchain-spike/EVIDENCE.md). They are toolchain measurements on the documented reference machine, not WireLens throughput or memory claims.

On the reference Apple M3 Pro MacBook Pro (11 cores, 18 GB RAM, macOS 26.6), both `web` target flows produced byte-identical 14,709-byte Wasm modules and 4,411-byte generated JavaScript bindings. Vite emitted separate 2,333-byte direct and 2,336-byte wasm-pack worker chunks, one fingerprinted 14,709-byte Wasm asset shared by both flows, and a 192,855-byte React entry chunk. The verifier found no executable remote reference.

The initial exact Ubuntu 24.04 x64 run exposed a host-path difference: Rust panic-location strings retained the native Cargo registry root. The build scripts now set encoded Rust path-remapping flags for the checkout and Cargo home. With those stable virtual roots, both measured hosts and both flows must produce JavaScript SHA-256 `57738e48798b60a3d9ae9abf0ffdc5ff75678b38a65a10c8d2d17e122d5d7093` and Wasm SHA-256 `7b2965e3e649d1ca85eb7dbbc2fe66df3794da4fea91f810a146023a01ffb08e`; the verifier rejects any drift.

`wasm-pack` 0.15.0's default downloaded `wasm-opt` failed validation on the bulk-memory instructions emitted by Rust 1.97.1. Re-running the documented comparison with `--no-opt` and `--mode no-install` succeeded, prevented hidden binding-tool acquisition, and produced the same processed Wasm hash as the direct flow: `7b2965e3e649d1ca85eb7dbbc2fe66df3794da4fea91f810a146023a01ffb08e`. This extra compatibility failure and hidden build-time download materially favor the explicit direct flow.

The production bundle loaded each module-worker variant in Chromium and Firefox, returned `265`, detached the transferred main-thread buffer, requested exactly one same-origin Wasm asset per run, and made zero external runtime requests. Browser/page/console failures are test failures.

The direct flow has fewer orchestration layers and makes every versioned stage visible. `wasm-pack` also works, but produces package metadata and owns more build/install behavior than WireLens needs for an internal application artifact. The `bundler` target is not selected because Vite's native static worker/asset path is clearer with `--target web`; adding a Wasm plugin solely to retain the bundler target would add an unnecessary production dependency.

## Decision

Use **direct Cargo plus exact-version `wasm-bindgen --target web`** for WireLens product Wasm builds.

The production integration contract is:

1. Compile the adapter with the pinned Rust toolchain and `wasm32-unknown-unknown` target.
2. Run `wasm-bindgen` at exactly the crate's locked version.
3. Let Vite fingerprint and serve the generated Wasm as a same-origin static asset.
4. Instantiate a standard module worker with the statically analyzable form:

   ```ts
   new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
   ```

5. Initialize the generated `web` binding inside that worker. Product Rust/Wasm calls must never execute on the browser main thread.
6. Commit source and lockfiles, not generated bindings, Wasm binaries, build output, Playwright traces, or downloaded tools.

No runtime CDN, package registry, telemetry, or remote Wasm location is permitted. A same-origin request for the application's own fingerprinted Wasm asset is expected and is not an upload. Strict post-load PWA caching is a separate product concern and is not implied by this toolchain decision.

## CI and contributor implications

- Clean CI installs Rust `1.97.1`, the Wasm target, exact `wasm-bindgen-cli` and `wasm-pack` versions, Node `24.18.0`, and pnpm `11.17.0`.
- The workspace is also checked separately on Rust `1.85` so build-tool requirements do not silently raise the core MSRV.
- Production worker tests run against built assets, not a development server.
- Browsers fail the probe if any request leaves the loopback origin or if worker/page/console errors occur.
- Contributors whose shell resolves Homebrew Rust before the `rustup` shims must correct `PATH`; otherwise `rust-toolchain.toml` cannot select the pinned toolchain.
- Generated glue is reproducible output and must never be hand-edited.

## Privacy, security, and performance impact

- The probe contains no captures or sensitive fixture data.
- Browser validation permits only the local production server and proves zero external runtime fetching.
- The recommendation does not claim that the eventual product works offline after an uncached first load; deployment/PWA validation remains separate.
- Artifact sizes and build times compare toolchains only. Parser throughput, boundary copies, peak memory, cancellation, and response budgets remain governed by ADR-0001 and later implementation benchmarks.

## Rejected alternatives

- **`wasm-pack` as the product build orchestrator:** viable, but adds package-oriented output and hides stages that are clearer as explicit Cargo and binding-generation commands.
- **`wasm-bindgen --target bundler` plus a Vite Wasm plugin:** rejected because the `web` output integrates without a special Wasm loader and keeps worker initialization explicit.
- **Unpinned latest/stable aliases:** rejected because Rust, binding schema, Node, and package-manager drift would make CI and local artifacts non-reproducible.
- **Main-thread Wasm initialization:** rejected by ADR-0001 because parsing and analysis must stay off the main thread.

## Consequences

- Issue #9 can implement the boundary against one proven binding generation and worker-loading contract.
- Issue #10 uses Vite's native module-worker discovery and same-origin asset pipeline in `apps/web`.
- A future version bump must update pins, regenerate lockfiles, rerun both comparison flows, and record browser evidence before changing this ADR's supported matrix.
