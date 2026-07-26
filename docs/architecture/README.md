# WireLens architecture

> **Decision status:** active. Accepted decisions below govern implementation; unresolved topics remain explicitly listed.

WireLens combines a React/TypeScript browser interface, a Web Worker, and platform-neutral Rust analysis crates compiled to WebAssembly. A later optional native Rust agent may provide authenticated live observations. ADR-0001 defines the normative offline boundaries.

## Principles to validate

- Offline capture bytes remain local to the user's browser.
- Untrusted parsing is memory-safe, bounded, testable, and independent from the UI.
- Browser parsing and analysis never block the main thread.
- Data crosses boundaries in batches without unnecessary full-capture copies or JSON expansion.
- Analysis conclusions retain packet evidence and communicate uncertainty.
- The offline product remains useful without a native component or network connection.

## Open decisions

1. **Frontend setup:** validate the production React/bundler configuration, worker/Wasm integration, testing, static deployment, and long-term maintenance.
2. **Wasm and worker protocol:** finalize commands/events, typed batches, handles, request identity, progress, cancellation, structured errors, backpressure, and versioning in #9.
3. **Large files:** streaming or chunking limits, memory budgets, incremental indexes, cancellation cleanup, and realistic browser constraints.
4. **IndexedDB persistence:** opt-in semantics, schema versions, quotas, migrations, deletion, and whether raw packet data is ever persisted.
5. **Visualization libraries:** packet-table virtualization, charts, sequence diagrams, topology rendering, accessibility, bundle size, and performance.
6. **Native-agent protocol:** local authentication, transport, schema evolution, batching, backpressure, replay resistance, and raw-packet exposure.
7. **Browser security model:** CSP, worker isolation, dependency risk, malicious captures, denial of service, export safety, and accidental network transmission.

## Decision discipline

Accepted ADRs are normative for browser/native responsibilities, crate and package boundaries, ownership, privacy, security, and measurable success criteria. New implementation must remain blocked when it depends on an unresolved decision, and material boundary changes require a superseding ADR.

## Accepted architecture decisions

- [ADR-0001: v0.1 offline architecture boundaries and engineering constraints](./adr-0001-v0.1-boundaries.md)
- [ADR-0002: repository and workspace structure map](./adr-0002-repository-workspace-structure.md)
- [ADR-0003: verification, fixture, fuzzing, and benchmark strategy](./adr-0003-verification-fixture-fuzz-benchmark-strategy.md)
- [ADR-0004: capture-container framing library](./adr-0004-capture-framing-library.md)
- [ADR-0005: canonical capture and packet data model](./adr-0005-canonical-capture-packet-model.md)
