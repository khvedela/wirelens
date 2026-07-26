# WireLens architecture

> **Decision status:** open. This document describes a provisional direction and the questions that must be resolved before application implementation.

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
2. **PCAP parsing crates:** correctness, PCAPNG coverage, malformed-input behavior, Wasm compatibility, maintenance, licensing, and zero/low-copy options.
3. **Parsed-data ownership:** packet-buffer ownership, borrowed views, arena/index strategies, cache lifetimes, and the safe zero-copy boundary.
4. **Wasm serialization:** handles, typed arrays, generated bindings, binary schemas, batching, and avoidance of whole-capture JSON serialization.
5. **Worker protocol:** command and event schemas, request identity, progress, cancellation, structured errors, backpressure, and versioning.
6. **Large files:** streaming or chunking limits, memory budgets, incremental indexes, cancellation cleanup, and realistic browser constraints.
7. **IndexedDB persistence:** opt-in semantics, schema versions, quotas, migrations, deletion, and whether raw packet data is ever persisted.
8. **Visualization libraries:** packet-table virtualization, charts, sequence diagrams, topology rendering, accessibility, bundle size, and performance.
9. **Native-agent protocol:** local authentication, transport, schema evolution, batching, backpressure, replay resistance, and raw-packet exposure.
10. **Browser security model:** CSP, worker isolation, dependency risk, malicious captures, denial of service, export safety, and accidental network transmission.

## Required first decision record

The initial architecture issue must produce an ADR that defines browser/native responsibilities, crate and package boundaries, data ownership across Rust/Wasm/worker/React, the platform-neutral core, privacy and security constraints, and measurable v0.1 success criteria. Implementation issues should remain blocked where they depend on those decisions.

## Accepted architecture decisions

- [ADR-0001: v0.1 offline architecture boundaries and engineering constraints](./adr-0001-v0.1-boundaries.md)
- [ADR-0002: repository and workspace structure map](./adr-0002-repository-workspace-structure.md)
- [ADR-0003: verification, fixture, fuzzing, and benchmark strategy](./adr-0003-verification-fixture-fuzz-benchmark-strategy.md)
