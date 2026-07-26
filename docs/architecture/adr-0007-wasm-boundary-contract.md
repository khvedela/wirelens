# ADR-0007: WebAssembly boundary contract

- **Status:** accepted
- **Date:** 2026-07-26
- **Issue:** [#9](https://github.com/khvedela/wirelens/issues/9)
- **Parent epic:** [#6](https://github.com/khvedela/wirelens/issues/6)
- **Conforms to:** [ADR-0001](./adr-0001-v0.1-boundaries.md), [ADR-0002](./adr-0002-repository-workspace-structure.md), [ADR-0003](./adr-0003-verification-fixture-fuzz-benchmark-strategy.md), [ADR-0004](./adr-0004-capture-framing-library.md), [ADR-0005](./adr-0005-canonical-capture-packet-model.md), and [ADR-0006](./adr-0006-rust-wasm-frontend-toolchain.md)

## Context

The canonical capture model is Rust-owned, immutable, and index-first. The browser needs a stable way to create that model, observe bounded progress, cancel work, and request bounded result pages without exposing Rust references or expanding the capture into JavaScript objects. Issue [#9](https://github.com/khvedela/wirelens/issues/9) owns this Wasm boundary. Issue [#10](https://github.com/khvedela/wirelens/issues/10) consumes it from the user-facing browser ingestion workflow, with separate [browser-ingestion evidence](../../benchmarks/browser-ingestion/EVIDENCE.md).

`pcap-parser` emits blocks that borrow its reader buffer. Those blocks are valid only during the current reader step and cannot become JavaScript views or long-lived model references. A Wasm call is also synchronous on its worker: while Rust is running, the same worker cannot receive a cancellation message. The boundary therefore needs explicit ownership, step, lifetime, and scheduling rules rather than a single long-running import call.

This ADR defines the required contract. It does not claim that the implementation already meets the latency, throughput, memory, transfer, or cleanup budgets. Those claims require the tests and measurements listed below.

## Decision summary

WireLens adopts a **versioned, worker-driven, generational-handle Wasm boundary**:

1. The worker gives the importer one complete input, which Rust owns for the import and resulting dataset lifetime.
2. Rust advances container parsing through bounded synchronous steps. This is incremental parsing, not streaming or asynchronously appended input.
3. The worker yields through a macrotask boundary between steps so cancellation messages can be received.
4. Import and dataset lifecycles use opaque generational handles with explicit states and deterministic disposal.
5. Control results use small structured messages; packet data uses versioned, bounded structure-of-arrays binary batches no larger than 8 MiB.
6. Progress and time values remain integer and exact. No canonical timestamp, offset, byte count, or identifier is converted through a JavaScript `Number` when that could lose information.
7. The command API version and binary batch schema version evolve independently.

The module worker remains the only JavaScript environment that initializes or calls product Wasm, as required by ADR-0001 and ADR-0006. `packet-core` remains platform-neutral and contains no worker, JavaScript, DOM, or `wasm-bindgen` dependency.

## Input ownership and parser lifetimes

### Complete Rust-owned input

Starting an import constructs a complete capture byte sequence in Rust-owned Wasm memory. The importer retains that allocation while parsing. On successful finalization, the same owned bytes become the canonical dataset storage described by ADR-0005; cancellation or fatal failure releases them.

The JavaScript-to-Wasm binding may require a copy into Wasm linear memory. The implementation must document the actual binding behavior and measure both persistent and transient allocations. This ADR does not describe that transition as zero-copy. The worker must release its input references as soon as the binding contract permits so an avoidable second complete buffer is not retained.

The ownership arrangement must be safe Rust. It must not create a self-referential importer in which a reader stores a reference into a movable byte owner. A parser block or packet borrowed from `pcap-parser` is translated into canonical values and absolute checked byte ranges before the reader consumes or refills its buffer. No borrowed parser value or pointer crosses a Wasm call boundary.

### Incremental parsing, not streaming ingress

The importer exposes a lifecycle equivalent to:

1. begin an import from a complete owned byte buffer;
2. advance it with a bounded step budget;
3. repeat until cancelled, failed, or ready to finalize;
4. validate and publish an immutable dataset handle.

A step is bounded by both work units, such as bytes or records, and implementation resource limits. A hostile single block must not bypass those limits: unsupported block sizes, allocation requests, or capture dimensions fail with a structured resource-limit error before unbounded work or growth occurs.

This use of a buffered reader satisfies ADR-0004 without parsing the entire capture in one slice or one uninterrupted call. It does **not** define an appendable parser, an asynchronous `Read` source, browser `Blob` chunking, or network-style streaming. If issue #10 or later large-file work needs streaming ingress, that requires a separate ownership and end-of-input contract; it must not be inferred from this step API.

## Cancellation and worker scheduling

Wasm cannot process a message while a synchronous call is executing on the same worker. Cooperative cancellation therefore follows this sequence:

1. the worker calls one bounded Rust step;
2. Rust returns progress, a terminal result, or a bounded batch;
3. the worker yields through a **macrotask** boundary, allowing queued cancel commands to run;
4. the worker checks cancellation before invoking the next Rust step;
5. cancellation transitions the import to a terminal cancelled state and disposes temporary Rust state.

Awaiting an already-resolved promise or chaining only microtasks is not a sufficient yield, because it can starve queued worker messages. The worker implementation must use a scheduling primitive that gives the worker event loop a new task turn.

Cancellation received while a Rust step is executing takes effect at the next step boundary; the API must not claim mid-instruction pre-emption. Step budgets and hostile-input limits must be tuned and measured against ADR-0001's 200 ms median cancellation-acknowledgement target. Cancellation before the first step, between steps, while a result batch is pending, and after terminal completion must have deterministic outcomes.

## Handles, states, and cleanup

Import work and completed datasets use distinct opaque handle types. A handle identifies a registry slot and generation. Callers must not inspect or derive meaning from its representation, and its wire encoding must not rely on a potentially lossy JavaScript number.

The minimum lifecycle is:

```text
import handle:  importing --finalize--> consumed + new live dataset handle
                    |                         |
                    +--> failed              +--> disposed
                    |
                    +--> cancelled

failed/cancelled import handle --> disposed
live dataset handle              --> disposed
```

A dataset handle is published only after the canonical dataset has passed its invariant validation. Finalization consumes the import handle; it cannot expose a partially valid dataset. Operations validate handle type, slot, generation, and allowed state before touching registry data. Reusing a vacant slot increments its generation so a stale handle cannot alias a new import or dataset.

Disposal is explicit and deterministic:

- disposing an active import releases its parser, temporary indexes, diagnostics, and owned capture bytes;
- disposing a dataset releases its capture bytes and arenas;
- disposal never affects another generation; repeated disposal returns a documented already-disposed or stale-handle result and releases nothing;
- operations other than disposal reject stale, foreign-type, or terminal handles with a structured error;
- registry entries, outstanding batches, diagnostics, and strings have hard resource limits;
- normal cleanup does not depend on JavaScript garbage collection or `FinalizationRegistry`.

The worker must call disposal from normal completion, cancellation, error, and teardown paths where JavaScript execution is still available. Terminating a worker remains a last-resort process-level reclamation mechanism, not the routine lifecycle contract.

## Command API and compatibility

Every request and response uses a small structured envelope containing the command API version, request identity, operation, status, and only the metadata required for that operation. Capture bytes, packet rows, and field trees are never serialized wholesale as JSON.

The command API and binary batch schema have separate version identifiers:

- **Command API version:** governs operations, request/response fields, handle semantics, state transitions, progress, and error categories.
- **Batch schema version:** governs binary headers, column identifiers, primitive encodings, alignment, and interpretation of batch bytes.

An unsupported major command version is rejected before mutation. Minor command evolution may be additive only when the receiving version explicitly defines unknown optional fields as ignorable; unknown required features are rejected. A batch decoder must reject an unsupported batch schema version rather than guessing its layout. Changing one version does not implicitly change the other.

The adapter must expose a version/capability query that requires no live handle. The issue #9 implementation records its exact exported names and generated TypeScript declarations in the reviewed [boundary API snapshot](../../benchmarks/wasm/boundary-harness/API.md), which the production contract verifier checks for drift; this ADR defines their evolution semantics.

## Progress contract

Import progress is a monotonic structured value with, at minimum:

- a phase;
- input bytes consumed;
- total input bytes;
- records processed.

Counters are non-negative integers and never decrease within one import generation. The canonical wire representation for values wider than 32 bits is lossless, such as `BigInt`-backed values or explicit high/low lanes. Percentage is a presentation derived by the worker or UI, not the canonical value. `bytes_consumed` never exceeds `total_bytes`, and a completed phase is reported only after canonical model validation succeeds.

Cancelled and failed imports retain their last valid counters in the terminal response but never report completion. Issue #10 may separately report browser file-read or transfer progress; it must not combine that value with Rust parse progress in a way that makes either counter non-monotonic or falsely complete.

## Structured errors, warnings, and diagnostics

Each operation returns an explicit success, progress, cancelled, or error status. Stable error categories must cover at least:

- invalid arguments and unsupported command or batch versions;
- invalid, stale, wrong-type, or wrong-state handles;
- malformed, truncated, or unsupported capture input;
- resource limits;
- cancelled work;
- invariant or internal failures.

Errors include a stable machine code, safe summary, operation/request context, and an exact input range when one is valid. Recoverable parse findings remain bounded canonical diagnostics or warnings and do not masquerade as successful decoding. Fatal errors do not publish a dataset handle.

Error strings, diagnostics, exceptions, and logs must not embed packet payloads or arbitrary capture bytes. Panics, unchecked offsets, integer wraparound, and allocation failure through attacker-controlled dimensions are not part of the public error model and must be prevented or converted at controlled boundaries.

## Binary batch contract

Dataset results use structure-of-arrays batches derived from canonical arena slices. A batch contains a small fixed header, the batch schema version, row count, and checked descriptors for typed columns. The encoding is explicitly little-endian and must not expose Rust `repr(C)` memory as an ABI. Readers validate all offsets, lengths, alignments, column types, and arithmetic before constructing views.

Each response has both a row limit and an encoded-byte limit. The complete response, including header, descriptors, compact metadata, and requested evidence bytes, must not exceed **8 MiB (8 × 1024 × 1024 bytes)**. Diagnostics, strings, and other variable-width data also have independent limits so a small row count cannot create an unbounded response.

Timestamps preserve ADR-0005's signed whole seconds, fractional ticks, decimal-or-binary resolution kind, and seven-bit exponent exactly. Signed interface timestamp offsets and other 64-bit values use a lossless representation. They must not pass through floating-point seconds, milliseconds, or JavaScript `Number` when that changes their value. Conversion to display units happens outside the canonical batch.

Long-lived or transferable batches cannot be views into `WebAssembly.Memory`: memory growth can invalidate those views, and its backing buffer is not a safe ownership-transfer boundary. The adapter therefore creates a bounded JavaScript-owned `ArrayBuffer` for a transferable result. That extraction is an explicit bounded copy. After transfer to the main thread, the worker must not retain the detached buffer or a duplicate result payload.

## Resource, copy, and memory evidence

Implementation of issue #9 must define hard limits for capture bytes, block sizes, record counts, registry entries, diagnostics, strings, step work, and batch sizes. Hitting a limit returns a structured resource-limit error and runs the normal cleanup path.

The implementation must measure and report, rather than assume:

- the number and size of persistent and transient full-input allocations during JavaScript-to-Wasm ingest;
- parser buffer growth and canonical dataset/index retention;
- batch extraction copies, worker transfer overhead, and detached-buffer cleanup;
- memory retained after cancellation, failure, repeated disposal, and repeated imports;
- peak worker plus Wasm memory against ADR-0001's 2.5× input-size budget;
- parser throughput, bounded-step duration, cancellation acknowledgement, and the 8 MiB response cap.

Measurements use the synthetic/provenance-governed fixtures and verification layers from ADR-0003. The issue #9 implementation records its reproducible results in the [Wasm boundary evidence report](../../benchmarks/wasm/boundary-harness/EVIDENCE.md); future boundary changes must regenerate that report rather than treating the original measurements as permanent.

### Implemented v1 limits and capabilities

The command capability query is the source of truth for the current build. API version 1 and batch schema version 1 expose these hard ceilings:

| Resource | Limit |
| --- | ---: |
| One capture | 256 MiB |
| Capture bytes retained by one boundary | 384 MiB |
| Known retained/reserved logical bytes | 512 MiB |
| One PCAP record or PCAPNG block | 4 MiB |
| Decoded PCAPNG options/list items per block / cumulative step | 4,096 / 4,096 |
| Packets | `min(131,072, 1,024 + floor(capture_bytes / 256))` |
| Sections / interfaces | 1,024 / 16,384 |
| Diagnostics / interned safe text | 1,024 / 256 KiB |
| Import handles / dataset handles / packet cursors | 16 / 1,024 / 65,536 |
| One import step | 4,096 records and 16 MiB |
| One packet batch | 65,536 rows and 8 MiB |
| One evidence read | 1 MiB |

Pre-copy admission checks handle capacity, total owned capture bytes, proportional packet capacity, and the conservative logical-memory ceiling before allocating the Rust input. The logical ceiling includes the parser circular buffer's spare-capacity/sentinel allowance, geometric packet-arena capacity, decoded option/name-record scratch, and bounded finalization state. A cumulative decoded-item checkpoint prevents many individually valid PCAPNG blocks from turning one step into unbounded option/list work. Runtime resource statistics distinguish current retained/reserved bytes from lifetime high-water counters. One validating checkpoint separates parser completion from atomic publication, and the worker applies transactional single-flight acknowledgement backpressure to packet-batch and evidence transfers.

## Scope split between issues #9 and #10

Issue [#9](https://github.com/khvedela/wirelens/issues/9) owns:

- the platform-neutral import lifecycle needed to build the ADR-0005 dataset;
- complete-input ownership and borrowed parser lifetime handling;
- bounded parse steps and resource limits;
- Wasm adapter commands, generational handles, states, progress, cancellation hooks, structured errors, cleanup, and version negotiation;
- bounded versioned structure-of-arrays batches;
- a minimal module-worker harness sufficient to verify the boundary built through ADR-0006;
- boundary correctness, malformed-input, cancellation, disposal, copy, transfer, and retained-memory evidence.

Issue #9 does not own a file picker, drag-and-drop, user-facing importer, packet table, persistence, or live-stream protocol.

Issue [#10](https://github.com/khvedela/wirelens/issues/10) owns:

- accessible file picker and drag-and-drop interactions;
- filename-independent capture magic validation;
- browser `File`/`Blob` acquisition and transfer into the worker;
- production worker orchestration around the issue #9 step API, including macrotask scheduling;
- user-facing read/parse progress, cancellation, and malformed/unsupported states;
- main-thread responsiveness and proof that offline capture data is not uploaded.

Any browser chunking used only to assemble the complete issue #9 input is an issue #10 implementation detail. An appendable Rust parser, persistent storage, packet-table rendering, protocol inspectors, and live capture remain outside both issues unless separately approved.

## Required verification before issue #9 completion

Acceptance evidence must include:

- cancellation before parsing, between bounded steps, while batches are produced, and after terminal states;
- stale, wrong-type, exhausted, and repeatedly disposed handles, including slot reuse across generations;
- malformed, truncated, mixed-endian, multi-section, multi-interface, high timestamp-resolution, signed-offset, oversized, and otherwise resource-limited synthetic inputs;
- exact round trips for timestamps, offsets, byte ranges, identifiers, and batch fields;
- command-version and batch-version mismatch behavior;
- batch layout validation, row/byte bounds, and absence of whole-capture JSON;
- repeated success, failure, cancellation, batch transfer, and cleanup memory baselines;
- execution from an ADR-0006 production module worker;
- applicable unit, integration, property, fuzz-replay, browser-boundary, and benchmark layers from ADR-0003.

The evidence must distinguish Rust parser/boundary performance in #9 from browser file handling and main-thread responsiveness in #10.

## Consequences

- Imports can remain cancellable without pretending synchronous Wasm is pre-emptible.
- Rust owns canonical bytes and parser lifetimes; JavaScript receives only opaque handles, small control metadata, and bounded copied batches.
- Dataset publication is atomic with respect to model validation.
- Compatibility failures and hostile-input limits become explicit API outcomes.
- Large-file streaming ingress remains an open architecture question instead of being accidentally promised by incremental parse stepping.
- Issue #10 can build user-facing ingestion against a defined lifecycle without absorbing Rust boundary design.

## Rejected alternatives

- **One synchronous import call:** rejected because the worker cannot service cancellation or progress messages until it returns.
- **Microtask-only yielding:** rejected because queued worker message tasks can remain starved.
- **Asynchronously appending bytes to the selected buffered reader:** rejected for issue #9 because reader exhaustion and borrowed lifetimes do not provide that contract.
- **Borrowed blocks or Wasm-memory views escaping a call:** rejected because their storage can be consumed, refilled, grown, or invalidated.
- **Whole-capture JSON or nested per-packet objects:** rejected for unbounded copying, allocation, and garbage-collection pressure.
- **Raw Rust struct layout as the binary ABI:** rejected because layout, padding, endianness, and compiler details are not a stable browser schema.
- **Slot-only handles:** rejected because stale callers could alias newly allocated state.
- **Floating-point canonical timestamps or offsets:** rejected because exact source semantics can be lost.
- **Garbage-collection-only cleanup:** rejected because capture memory must have deterministic lifetime behavior.
