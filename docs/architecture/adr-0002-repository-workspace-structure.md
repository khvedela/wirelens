# ADR-0002: repository and workspace structure map

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#4](https://github.com/khvedela/wirelens/issues/4)
- **Parent epic:** [#1](https://github.com/khvedela/wirelens/issues/1)
- **Blocked by:** [#2](https://github.com/khvedela/wirelens/issues/2)

## Context

WireLens now has accepted v0.1 architecture boundaries in ADR-0001, but repository and workspace boundaries still need an explicit map before initializing crates or frontend packages. Without a canonical layout, browser dependencies can leak into parser crates, fixture governance becomes inconsistent, and benchmark or documentation ownership is harder to enforce.

## Decision

Define the canonical future repository layout, Rust workspace crate responsibilities, allowed dependency direction, naming conventions, and shared-schema ownership as follows.

### Repository and workspace layout

```text
wirelens/
├── apps/
│   └── web/                        # Frontend package (React + worker + browser-only code)
├── crates/
│   ├── packet-core/                # Capture primitives, cursors, normalized packet model
│   ├── protocol-decoders/          # Ethernet/VLAN/ARP/IP/ICMP/TCP/UDP/DNS decoding
│   ├── flow-engine/                # Flow/session reconstruction and indexes
│   ├── analysis-engine/            # Filter execution and evidence-linked summaries
│   ├── wasm-adapter/               # Wasm ABI, handle lifecycle, typed-array boundary
│   ├── wirelens-cli/               # Optional offline-native CLI using platform-neutral crates
│   └── capture-agent/              # Deferred optional native live-capture component
├── fixtures/
│   ├── synthetic/                  # Generated fixtures safe for redistribution
│   ├── redistributable/            # Third-party fixtures with explicit redistribution rights
│   └── manifests/                  # Provenance, licensing, and sensitivity annotations
├── benchmarks/
│   ├── parser/                     # packet-core/protocol decoder performance inputs
│   ├── flow/                       # flow-engine and analysis-engine workload definitions
│   ├── wasm/                       # worker↔Wasm boundary throughput/latency workloads
│   └── ui/                         # browser rendering and interaction benchmark scenarios
└── docs/
    ├── architecture/               # ADRs and architecture boundary decisions
    ├── product/                    # Vision, requirements, UX notes
    └── roadmap.md                  # Cross-epic sequencing and dependency order
```

### Allowed dependency direction

Dependency direction is inward toward platform-neutral core crates:

- `apps/web` -> worker protocol schema + `crates/wasm-adapter` bindings only.
- `crates/wasm-adapter` -> `analysis-engine` -> `flow-engine` -> `protocol-decoders` -> `packet-core`.
- `crates/wirelens-cli` -> platform-neutral crates (`analysis-engine`, `flow-engine`, `protocol-decoders`, `packet-core`).
- `crates/capture-agent` (deferred) -> platform-neutral crates and shared schema crates only.
- `packet-core` must not depend on `wasm-adapter`, `apps/web`, browser APIs, React, DOM, or JavaScript tooling.

Disallowed edges:

- Any core crate (`packet-core`, `protocol-decoders`, `flow-engine`, `analysis-engine`) depending on frontend code or browser/Wasm toolchain crates.
- `apps/web` importing Rust parser internals directly.
- Cross-layer shortcuts that bypass `wasm-adapter` for browser execution.

### Shared schema ownership

- Canonical worker command/event schemas are owned by architecture and worker-boundary work, then consumed by:
  - `apps/web` TypeScript types and message handlers.
  - `crates/wasm-adapter` boundary translation layer.
  - Deferred native components only through explicit compatibility contracts.
- Schema evolution must remain versioned and additive unless a new ADR approves a breaking transition plan.

### Naming conventions

- Rust crate directories and package names: kebab-case (`packet-core`, `analysis-engine`).
- Frontend package directories: short, purpose-based kebab-case under `apps/` (`web`).
- Fixture files: lowercase snake_case filenames with protocol/context suffix where useful.
- Benchmark scenario files: lowercase kebab-case, grouped by subsystem directory.
- ADR files: `adr-####-short-kebab-title.md`.

### Boundary guardrails

- Keep browser-only dependencies (`react`, DOM APIs, frontend bundler plugins) inside `apps/web`.
- Keep platform-neutral crates free of Wasm/browser/frontend dependencies.
- Treat fixture governance as mandatory:
  - no private/proprietary captures,
  - no unknown-license captures,
  - provenance and sensitivity metadata required in `fixtures/manifests`.
- Every protocol parsing change must include malformed/truncated tests and parser/flow/Wasm benchmark coverage where performance-sensitive.

## Consequences

- Workspace/package initialization tasks must create crates and packages only in the paths above unless superseded by a new ADR.
- Reviewers can validate dependency boundaries using this map before code-level enforcement is introduced.
- Fixture, benchmark, and documentation locations are now explicit and auditable.
- Browser and frontend dependencies are constrained away from core parsing and analysis crates by documented policy.

## Out of scope

- Initializing crates/packages in this issue.
- Selecting concrete parser libraries or frontend build stack details.
- Defining final worker schema payload details (tracked separately).
