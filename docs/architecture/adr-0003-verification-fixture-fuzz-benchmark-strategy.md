# ADR-0003: verification, fixture, fuzzing, and benchmark strategy

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#5](https://github.com/khvedela/wirelens/issues/5)
- **Parent epic:** [#1](https://github.com/khvedela/wirelens/issues/1)

## Context

WireLens must treat captures as hostile input while preserving privacy-first local analysis claims. The project needs a shared evidence standard that defines verification layers, fixture governance, parser correctness expectations, fuzzing responsibilities, and performance regression handling before implementation begins.

## Decision summary

WireLens adopts a six-layer verification model, strict fixture provenance policy, scheduled fuzzing split from per-PR CI, and initial parser/flow/Wasm performance budgets. Any parsing or boundary change must provide evidence from the applicable layers.

## Verification layers and scope

### 1. Unit tests (crate/package local)

Purpose:

- Validate parser primitives, protocol field decoding, cursor bounds checks, and error typing at the smallest surface.
- Cover malformed/truncated edge cases for each changed protocol branch.

Required when:

- Any parsing, indexing, filtering, or boundary utility logic changes.

### 2. Integration tests (cross-crate behavior)

Purpose:

- Validate end-to-end capture import, decode pipelines, and filter/query behavior across crate boundaries.
- Verify deterministic evidence links (packet ids/ranges/offsets) from analysis outputs.

Required when:

- Changes span multiple crates or alter observable parse/filter behavior.

### 3. Browser/worker boundary tests

Purpose:

- Validate worker orchestration, cancellation signaling, typed-array transfer contracts, and main-thread non-blocking behavior.
- Confirm no whole-capture JSON expansion and no network transmission of capture bytes.

Required when:

- Worker protocol, Wasm adapter, batching, cancellation, or browser integration changes.

### 4. Property-based tests

Purpose:

- Assert invariants that must hold across many generated inputs (for example: bounded cursor progression, parser totality over byte slices, idempotent normalization rules).
- Stress malformed and adversarial structure combinations not covered by fixed examples.

Required when:

- Parser state machines, normalization rules, or flow aggregation invariants are modified.

### 5. Fuzz testing

Purpose:

- Detect panic, out-of-bounds, unbounded allocation, and denial-of-service paths in untrusted parsing/decoding logic.
- Exercise both format-level and protocol-level corruption patterns.

Execution split:

- **CI per PR:** short smoke fuzz corpus replay / regression seeds with tight time limits.
- **Scheduled workflows:** longer-running fuzz campaigns (nightly/weekly) with corpus growth and crash triage.

### 6. Benchmarks

Purpose:

- Measure parser throughput, flow reconstruction cost, Wasm boundary transfer overhead, and UI-facing latency budgets.
- Detect regressions before merge and over time.

Required when:

- Parsing, indexing, filtering, Wasm transfer, or worker batching behavior changes.

## Fixture policy

### Synthetic capture generation (default)

Synthetic fixtures are the default for tests and benchmarks.

Rules:

1. Generate from scripts/tools that are deterministic and documented.
2. Record protocol intent per fixture (what behavior/edge case it proves).
3. Cover malformed, truncated, adversarial, and large-input scenarios with synthetic data.
4. Store generation metadata and fixture purpose in `fixtures/manifests`.

### Explicitly redistributable captures (exception path)

Third-party fixtures are allowed only with explicit redistribution rights.

Requirements:

1. License terms must permit redistribution in this repository.
2. Provenance metadata must include source, license, acquisition date, and integrity hash.
3. Sensitive content must be removed/replaced; fixtures with private/proprietary traffic are forbidden.
4. Unknown-license captures are rejected.

## Parser correctness expectations

For parser-affecting changes, evidence must show:

1. No panic on malformed/truncated inputs in supported formats/protocol paths.
2. Explicit, structured error/diagnostic reporting instead of silent corruption.
3. Best-effort continuation where safe, with clear failure boundaries.
4. Stable packet-evidence references for downstream analysis claims.
5. Deterministic outputs for identical inputs and configuration.

## Initial performance budgets

Budgets are validated on a documented reference machine/profile and revisited through follow-up issues when data justifies changes.

- **Parser ingest throughput:** >= 50 MB/s on large-capture ingest+index baseline.
- **First query/filter response:** <= 1 s for indexed header-field predicates on reference dataset.
- **Cancellation responsiveness:** median <= 200 ms from cancel request to acknowledgement.
- **Peak memory envelope:** <= 2.5x input capture size across browser+worker+Wasm path.
- **Boundary payload cap:** single worker->main-thread response payload <= 8 MB.

## Regression reporting expectations

Every parsing/boundary/performance-sensitive PR must include:

1. Which verification layers were executed and why they are sufficient.
2. Fixture provenance statement (synthetic or redistributable manifest reference).
3. Benchmark comparison against baseline for affected budgets.
4. Any budget misses with explanation, mitigation, and linked follow-up issue.
5. Fuzz findings/crashes, including reproduction seed and triage status when applicable.

## Consequences

- Contributors must select the minimum applicable verification layers based on risk and changed boundaries; happy-path-only evidence is insufficient.
- Fixture provenance becomes review-blocking for all committed captures.
- CI and scheduled fuzzing have distinct responsibilities: fast merge protection versus deep resilience discovery.
- Performance claims must be backed by benchmark deltas rather than intuition.

## Out of scope

- Implementing fuzz targets, benchmark harnesses, protocol decoders, or CI jobs in this ADR.
- Finalizing tool/library choices for property testing or fuzz engines.
