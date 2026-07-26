# ADR-0005: canonical capture and packet data model

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#8](https://github.com/khvedela/wirelens/issues/8)
- **Parent epic:** [#6](https://github.com/khvedela/wirelens/issues/6)
- **Depends on:** [ADR-0004](./adr-0004-capture-framing-library.md)

## Context

Protocol decoding, flow reconstruction, filtering, evidence inspectors, and the worker/Wasm boundary need stable packet identities and exact source evidence without expanding a capture into JavaScript objects. PCAPNG also prevents capture-wide assumptions: sections can use different byte order and interfaces can use different link types, snap lengths, and timestamp resolutions.

## Decision

The canonical model lives in platform-neutral `packet-core` and is an immutable, index-first dataset:

- one Rust-owned capture byte buffer;
- fixed-width arenas for sections, interfaces, packets, layers, decoded fields, field-child IDs, and diagnostics;
- checked half-open byte ranges into the original buffer;
- dataset-local integer IDs and consecutive arena ranges instead of object references;
- deduplicated strings for protocol/field labels and safe diagnostic text;
- exact timestamps retaining decimal or binary source resolution;
- packet facts separated from future derived flow/analysis facts.

The Rust types and invariant tests are implemented under `crates/packet-core`. The crate has no DOM, browser, JavaScript, WebAssembly, React, or UI dependency.

## Identity and timestamp semantics

`PacketId` is a stable zero-based dataset-local identity. Presentation layers may display `id + 1`, but sorting, filtering, and cross-view selection must retain the stable ID.

`CaptureTimestamp` stores whole Unix seconds, fractional ticks, and the original `TimestampResolution`. Fractions must be normalized below one second. Decimal (`10^-n`) and binary (`2^-n`) PCAPNG resolutions remain distinguishable; conversion for display must not replace the canonical value.

## Evidence and field semantics

All byte ranges are absolute, half-open `[start, end)` offsets into the owned capture buffer. A decoded field owns a span in a separate compact child-ID arena, so arbitrary hierarchies remain representable without a heap allocation per node. Validation rejects cycles, duplicate parents, overlapping spans, and orphan child slots. Raw or unsupported values remain referenceable as byte ranges.

`LayerFact` is protocol-extensible: an interned protocol identifier, evidence range, and optional field-tree root describe link, network, transport, and later application layers without embedding frontend view models.

## Diagnostics and uncertainty

Diagnostics have stable machine codes, severity, capture/packet scope, optional exact evidence, safe interned text, and a recovery outcome. Malformed, truncated, unsupported, inconsistent, and resource-limited states are explicit. Protocol or analysis code must not imply successful decoding when a diagnostic contradicts it.

## Boundary serialization strategy

The canonical Rust dataset is not serialized wholesale. Issue #9 must expose versioned, bounded structure-of-arrays batches (typed numeric arrays plus compact metadata) built from packet/field arena slices. Raw bytes cross only for explicitly requested evidence ranges. Opaque dataset handles own lifetimes; JSON is limited to small control and diagnostic metadata.

This keeps core ownership independent from a particular Wasm binding or future native caller while avoiding whole-capture JSON allocation.

## Memory review

`PacketRecord` is fixed width and owns no per-packet heap allocation. A one-million-packet index therefore grows linearly in contiguous arenas; its invariant test caps packet-record metadata at 96 MiB before layer/field indexes. The capture byte buffer remains the dominant required allocation. Issue #9 benchmarks total dataset and boundary memory against ADR-0001’s 2.5× capture-size envelope.

## Consequences

- Decoders append facts and field nodes to arenas and preserve byte evidence.
- Flow and analysis crates reference `PacketId`; they do not mutate immutable packet facts.
- Multi-interface and mixed-resolution captures remain correct by construction.
- Worker batches can page predictable numeric columns without cloning the dataset.
- Persistence remains out of scope and requires a separately versioned schema.

## Rejected alternatives

- Per-packet nested object graphs: rejected for allocation overhead and unstable cross-boundary ownership.
- Capture-wide link type or timestamp resolution: rejected as incorrect for PCAPNG.
- Nanoseconds-only canonical timestamps: rejected because conversion can lose original precision and semantics.
- Whole-dataset JSON/Serde as the browser contract: rejected for duplication, GC pressure, and unbounded response size.
