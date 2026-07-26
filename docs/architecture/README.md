# WireLens architecture

> **Decision status:** partially resolved. Core v0.1 boundaries and EPIC 2 ingestion decisions are accepted; remaining items below stay open.

WireLens is expected to combine a React/TypeScript browser interface, a Web Worker, and platform-neutral Rust analysis crates compiled to WebAssembly. A later optional native Rust agent may provide authenticated live observations. These boundaries are hypotheses, not final decisions.

## Principles to validate

- Offline capture bytes remain local to the user's browser.
- Untrusted parsing is memory-safe, bounded, testable, and independent from the UI.
- Browser parsing and analysis never block the main thread.
- Data crosses boundaries in batches without unnecessary full-capture copies or JSON expansion.
- Analysis conclusions retain packet evidence and communicate uncertainty.
- The offline product remains useful without a native component or network connection.

## Open decisions

1. **Frontend setup:** React with Vite versus another frontend/build configuration; assess worker and Wasm integration, testing, static deployment, and long-term maintenance.
2. **IndexedDB persistence:** opt-in semantics, schema versions, quotas, migrations, deletion, and whether raw packet data is ever persisted.
3. **Visualization libraries:** packet-table virtualization, charts, sequence diagrams, topology rendering, accessibility, bundle size, and performance.
4. **Native-agent protocol:** local authentication, transport, schema evolution, batching, backpressure, replay resistance, and raw-packet exposure.
5. **Browser security model:** CSP, worker isolation, dependency risk, malicious captures, denial of service, export safety, and accidental network transmission.

## Required first decision record

The initial architecture issue must produce an ADR that defines browser/native responsibilities, crate and package boundaries, data ownership across Rust/Wasm/worker/React, the platform-neutral core, privacy and security constraints, and measurable v0.1 success criteria. Implementation issues should remain blocked where they depend on those decisions.

## Accepted architecture decisions

- [ADR-0001: v0.1 offline architecture boundaries and engineering constraints](./adr-0001-v0.1-boundaries.md)
- [ADR-0002: repository and workspace structure map](./adr-0002-repository-workspace-structure.md)
- [ADR-0003: verification, fixture, fuzzing, and benchmark strategy](./adr-0003-verification-fixture-fuzz-benchmark-strategy.md)
- [ADR-0004: EPIC 2 capture ingestion and Rust/Wasm pipeline](./adr-0004-epic-2-capture-ingestion-rust-wasm-pipeline.md)
