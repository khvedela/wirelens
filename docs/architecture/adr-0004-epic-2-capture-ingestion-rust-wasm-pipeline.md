# ADR-0004: EPIC 2 capture ingestion and Rust/Wasm pipeline

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#6](https://github.com/khvedela/wirelens/issues/6)
- **Child issues:** [#7](https://github.com/khvedela/wirelens/issues/7), [#8](https://github.com/khvedela/wirelens/issues/8), [#9](https://github.com/khvedela/wirelens/issues/9), [#10](https://github.com/khvedela/wirelens/issues/10)

## Context

EPIC 2 requires local PCAP/PCAPNG ingestion that keeps capture bytes private, preserves browser responsiveness, and defines a concrete Rust/Wasm boundary that can be implemented incrementally. ADR-0001 already fixed high-level boundaries (worker-centered orchestration, handle/index API, platform-neutral Rust core), but parser/library choice, canonical model details, Wasm boundary contracts, and worker ingestion flow remained unresolved.

## Decision summary

WireLens v0.1 resolves EPIC 2 as follows:

1. **Parser library:** adopt `pcap-parser` as the ingestion parser in `packet-core`, with explicit malformed/truncated-input handling and no browser-side parsing fallback.
2. **Canonical model:** use a packet-indexed capture model that stores immutable capture metadata, packet-row index fields, and byte-range evidence references into owned capture buffers.
3. **Wasm boundary:** keep the worker-centered handle/index API with explicit ownership, bounded batch transfer, structured errors, progress events, and cooperative cancellation.
4. **Worker ingestion:** ingest files in a dedicated Web Worker, transfer bytes (not copies where transferable), stream progress to UI, and support cancellation and cleanup.
5. **Responsiveness/privacy verification:** verify non-blocking behavior and no-upload guarantees through boundary and browser tests aligned with ADR-0003.

## Parser library selection (issue #7)

`pcap-parser` is selected because it:

- Supports both PCAP and PCAPNG decoding paths.
- Is designed for robust parsing of untrusted captures with explicit error outcomes.
- Fits the `packet-core` requirement to remain platform-neutral and reusable outside the browser.
- Supports incremental/stream-oriented parsing patterns needed for cooperative cancellation checkpoints.

Selection constraints:

- Parsing errors must map to structured WireLens error categories rather than panics.
- Unsupported link types or malformed blocks must produce explicit diagnostics with bounded failure behavior.
- Any future parser-library replacement requires a new ADR or explicit amendment to this ADR.

## Canonical capture and packet model (issue #8)

The canonical model is index-first and evidence-preserving:

- **Capture metadata:** dataset id/handle, source format (`pcap` or `pcapng`), link-layer type(s), packet count, import diagnostics, and ingest timing metrics.
- **Packet row fields (index):** stable packet ordinal, timestamp (seconds/nanoseconds resolution as available), captured length, original length, direction/flow placeholders, and decode-status flags.
- **Evidence references:** packet rows reference immutable byte ranges (offset + length) within owned capture buffers so downstream decoding and UI evidence views do not require full-copy JSON expansion.
- **Diagnostics:** malformed/truncated packets are represented with structured per-packet diagnostics while preserving safe best-effort continuation boundaries.

This model is canonical for worker↔Wasm exchange and downstream protocol/flow layers; presentation-specific shape remains a UI concern.

## Wasm boundary contract (issue #9)

The EPIC 2 boundary contract is:

- **Ownership:** Wasm owns dataset/query handles and backing indexes; worker owns request correlation and lifecycle orchestration; UI receives bounded presentation batches.
- **Import API:** worker invokes import with request id and byte ownership transfer, receives `dataset_handle` plus progress and completion/cancel/error events.
- **Batching:** packet/query results are returned as bounded typed-array-backed batches with small structured metadata, never whole-capture object graphs.
- **Errors:** all boundary failures map to a stable error taxonomy (`input_format`, `resource_limit`, `cancelled`, `internal`) with message and context fields safe for UI display.
- **Cancellation:** worker can cancel import/query by request id; Rust checks cancellation between parse/index chunks and returns deterministic cancelled status with cleanup.
- **Lifecycle:** explicit close/free operations invalidate handles and reclaim resources; use-after-free returns structured invalid-handle errors.

## Browser worker ingestion flow (issue #10)

Import flow for v0.1:

1. Main thread obtains user-selected file and transfers bytes/chunks to worker.
2. Worker starts import request, forwards data to Wasm parser/index pipeline, and emits progress snapshots to UI.
3. UI remains responsive by rendering progress state only; parsing/indexing never executes on the main thread.
4. Cancel from UI is routed to worker then Wasm; cancellation is acknowledged quickly and partial resources are reclaimed.
5. On completion, worker returns dataset handle and initial summary metadata; packet pages are fetched lazily via batch APIs.

Hard requirements:

- No network upload path for capture bytes in offline ingestion.
- Bounded memory growth via chunked processing and bounded response payloads.
- Deterministic behavior for malformed captures with explicit error reporting.

## EPIC 2 exit-criteria mapping

- **Parser library and canonical model selected:** satisfied by the `pcap-parser` selection and canonical model definition above.
- **Wasm boundary has ownership, batching, errors, progress, cancellation:** satisfied by the boundary contract above.
- **Worker ingestion handles supported and malformed captures locally:** satisfied by the import flow and hard requirements above.
- **Responsiveness and no-upload behavior verified:** must be evidenced by ADR-0003 layer-3 boundary/browser tests before implementation work is declared complete.

## Consequences

- EPIC 2 implementation issues must conform to this ADR and ADR-0001/0002 boundaries.
- Protocol decoding and flow-analysis work may assume the canonical packet index/evidence model defined here.
- Any proposal to move parsing to main thread, expand whole-capture JSON transfer, or upload capture bytes requires a new ADR.

## Out of scope

- Protocol breadth and deep decoder coverage (EPIC 3).
- Flow reconstruction and conversation analytics (EPIC 4).
- Persistence, live capture, cloud processing, and optional eBPF work (deferred epics).
