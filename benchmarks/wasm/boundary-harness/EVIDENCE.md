# Wasm boundary evidence

Recorded 2026-07-26T22:27:25.813Z in chromium. The browser reported `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/150.0.0.0 Safari/537.36` and 11 logical processors. Fixtures are deterministic, generated in memory, and contain no captured private traffic.

> This is supported-boundary workload evidence below 500 MB. It does not satisfy or redefine
> ADR-0001's successful `>=500 MB` large-capture criterion; ADR-0008 and issue #55 keep that
> product-level L2/T1/M1 decision open.

This report is emitted only after the exact toolchain check, direct Cargo + `wasm-bindgen` production build, static binary-transport/API-signature contract check, TypeScript check, production bundle, and all assertions below pass.

## Acceptance measurements

| Measurement | Result | Limit |
| --- | ---: | ---: |
| Sparse ingest + index throughput (15,367,704 bytes) | 13721.2 MB/s | >= 50 MB/s |
| Largest dense synchronous step | 5.82 ms | <= 200 ms |
| Dense finalization checkpoint | 5.82 ms | <= 200 ms |
| Median queued cancellation acknowledgement | 2.69 ms | <= 200 ms |
| Cancellation while terminal batch is pending | 5.80 ms | <= 200 ms |
| Largest option-dense hostile-tail step (2,101,248 decoded items behind the checkpoint) | 0.29 ms | <= 200 ms |
| Option-dense hostile-tail cancellation | 0.03 ms | <= 200 ms |
| Browser agent-cluster sampled high-water growth / dense capture | 1.49x | <= 2.5x |
| Wasm linear-memory sampled high-water growth / dense capture | 1.44x | <= 2.5x |
| Conservative modeled synchronous envelope / dense capture | 2.12x | <= 2.5x |
| Retained capture + canonical index / dense capture | 1.26x | <= 2.5x |
| Packet batch | 3,060,352 bytes | <= 8,388,608 bytes |
| Packet-batch extraction + transfer | 509.2 MB/s | measured |
| Evidence extraction + transfer | 3956.9 MB/s | measured |
| Same-size success + binary-transfer Wasm high-water growth | 0 bytes | 0 bytes |
| Queued-cancellation Wasm high-water growth | 0 bytes | 0 bytes |
| Fatal resource-limit Wasm high-water growth | 0 bytes | 0 bytes |

The dense fixture contains 60,000 near-MTU Ethernet records with 1,440 authored payload bytes each, totaling 88,200,024 bytes. Its proportional admission ceiling was 131,072 packets. The sparse fixture contains 256 large records in 15,367,704 bytes. Both passed through an explicit `validating` checkpoint before a later call atomically published the dataset.

The 8,415,280 bytes PCAPNG hostile fixture contains 2,101,248 individually valid options across 513 blocks. Twelve calls each made monotonic byte progress while the cumulative 4,096-item work checkpoint prevented decoding the remaining tail in one worker task; cancellation then returned the boundary to its exact baseline.

## Ownership and allocation accounting

This is a source-inspected allocation model corroborated by runtime detachment checks. Detachment proves transfer semantics and the ownership hand-off; JavaScript does not expose whether a browser engine performs a physical implementation copy.

| Boundary transition | Modeled copies or allocations | Evidence |
| --- | ---: | --- |
| Main thread -> worker | 0 structured-clone copies | Transfer list used; source `ArrayBuffer` detached |
| Worker JavaScript -> Rust ownership | 1 copy | Explicit admitted `Uint8Array.copy_to` of 88,200,024 bytes |
| Synchronous ingest peak | 2 full buffers | Transferred worker input plus Rust destination coexist only during the call |
| After `beginImport` returns | 1 full buffer | Resource stats report exactly 88,200,024 bytes Rust-owned input |
| Rust packet batch -> worker JavaScript | 1 bounded copy | 3,060,352 bytes, then source detached on transfer |
| Rust evidence view -> worker JavaScript | 1 bounded copy | 1,048,576 bytes, then source detached on transfer |
| Worker -> main binary output | 0 structured-clone copies | Both transfer-detachment audits passed |

The static contract verifier rejects whole-capture JSON/text conversion; `wholeCaptureJson` was false. Rust batches move out of the registry before copying to a JavaScript-owned transferable buffer, so retained batch bytes remained zero.

## Retained and reserved bytes

| Resource | Bytes |
| --- | ---: |
| Published dense capture | 88,200,024 bytes |
| Dense packet-record arena | 5,242,880 bytes |
| All dense canonical indexes and strings | 23,069,379 bytes |
| Dense retained logical total | 111,269,403 bytes |
| Parser-buffer upper bound after begin | 8,388,610 bytes |
| Packet-index reservation after begin | 10,485,760 bytes |
| Auxiliary/finalization reservation after begin | 79,873,345 bytes |
| Total logical upper bound after begin | 186,947,739 bytes |

After dense disposal, 9 queued-cancellation samples, 6 fatal resource-limit samples, sparse disposal, and each of 6 same-size success/transfer sessions, all live handle counts and retained/reserved byte counters returned to the original baseline. Cancellation and fatal-error samples also stayed at or below the Wasm high-water established by the same-size successful workload. Wasm linear memory is deliberately reported as a reusable high-water allocation; it is not described as reclaimable retained capture state.

## Privacy and transfer checks

- The page was cross-origin isolated and the Wasm ran in a production `type: "module"` worker.
- The browser emitted 0 uncaught page, worker, or console errors during the complete evidence run.
- The test blocked external requests and observed 0 external requests, 0 non-GET/body-bearing requests, 0 HTTP requests after the worker became ready, and 0 WebSocket channels. Because every import ran after that checkpoint, no audited HTTP or WebSocket path could carry capture bytes.
- Main-to-worker input, worker-to-main batch, and worker-to-main evidence transfers all detached their source buffers. This confirms transfer/ownership semantics, not unobservable physical engine-copy behavior.
- The independently implemented worker-side batch decoder validated the returned header, descriptors, alignment, ranges, row sequence, and evidence references before transfer. The main thread performed only the constant-work header and twelve-descriptor envelope check before commit.

## Memory sampling notes

Browser memory came from `measureUserAgentSpecificMemory`. The reported runtime number is an agent-cluster sampled high-water relative to the already-loaded, idle boundary, using samples at input creation, the validating checkpoint, and binary transfer; it is not labeled as an unsampled instantaneous peak. Wasm memory was sampled after every dense step and before and after every same-size repeated success/transfer session.

The conservative synchronous envelope is 186,947,739 bytes. It takes the maximum of the two-full-input `beginImport` overlap, the parser's exact retained-plus-reserved logical upper bound, and published logical state plus two bounded output buffers at the larger binary-output cap (8,388,608 bytes). Runtime samples, this source-inspected model, and exact logical counters are distinct evidence and none is presented as a substitute for the others.
