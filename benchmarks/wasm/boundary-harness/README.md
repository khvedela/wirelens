# Wasm boundary browser harness

This engineering harness verifies WireLens's production WebAssembly boundary inside a real
`type: "module"` Web Worker. It does not implement the user-facing capture importer. All capture
fixtures are deterministic PCAP byte arrays generated in TypeScript; no packet capture file is
stored or uploaded.

The worker imports the real `crates/wasm-adapter` artifact built by direct Cargo followed by the
exact pinned `wasm-bindgen --target web`, as selected by ADR-0006. Its request envelope carries the
command API version on every call, and packet reads additionally
carry the binary batch schema version. Capture input, evidence, and packet batches remain binary;
the transport contains no whole-capture JSON or text conversion.

## Reproduce

From the repository root, select the pinned Node version, then run:

```sh
nvm use
cd benchmarks/wasm/boundary-harness
corepack pnpm install --frozen-lockfile
corepack pnpm run tools:install
corepack pnpm verify
```

`tools:install` delegates to the adjacent toolchain spike so both probes share one pinned
`wasm-bindgen` installation. Browser tests run in Chromium and Firefox and block all
non-local network requests.

For a Chromium timing, memory, ownership, and copy report, run:

```sh
corepack pnpm evidence
```

The raw measurements and a CI-friendly report are written under ignored `test-results/`; the same
report is committed as [`EVIDENCE.md`](EVIDENCE.md). The evidence script checks ingest+index
throughput (at least 50 MB/s), bounded step/finalization time and queued cancellation acknowledgement
(at most 200 ms), a multi-million-item PCAPNG hostile tail, bounded batches (at most 8 MiB),
dense-record index amplification, transfer cost, logical cleanup, detached transfers, successful,
cancelled, and fatal-error Wasm memory plateaus, sampled browser/Wasm high-water growth, and a conservative source-inspected
synchronous memory envelope (at most 2.5 times the synthetic capture). Wasm linear-memory high-water
allocation is reported separately from live logical capture ownership. Buffer detachment demonstrates
transfer semantics; the report does not claim that unobservable browser-engine implementation copies
were measured. A qualifying memory report requires Chromium's cross-origin-isolated
`measureUserAgentSpecificMemory` API; a main-realm heap-only fallback is not accepted as worker/Wasm
evidence.

The exact generated `wasm-bindgen` exports and the version-1 worker operation set are recorded in
the reviewed [`API.md`](API.md) snapshot. The contract verifier compares each production-generated
TypeScript declaration with that snapshot before browser tests run.

## Ownership and cancellation checkpoints

The main thread transfers its `ArrayBuffer` into the worker and verifies source detachment. After
pre-copy admission, the facade allocates one Rust-owned input and explicitly copies the worker
`Uint8Array` into it. Import work is split into hard record/byte-bounded synchronous steps. Reaching
the parser-ready state returns a `validating` checkpoint; a later call performs bounded validation
and publishes the dataset, so a queued cancel can run between them. Packet batches and evidence are
copied into bounded JavaScript-owned byte arrays, transferred to the main thread, and audited for
source detachment. The worker performs the bounded row-level batch validation; the main thread checks
only the fixed header and twelve descriptors. The worker and client permit only one unacknowledged
binary response at a time.

The behavioral suite covers compatibility rejection before mutation, monotonic lossless progress,
cancellation before/between/after terminal work, malformed input, wrong/stale handles, idempotent and
cascading disposal, batch-version rejection without cursor advancement, exact evidence reads,
independent binary-schema validation, fail-closed batch transactions, global/proportional resource
admission, uncaught page/worker/console errors, and repeated sessions returning live-resource
accounting to baseline.
