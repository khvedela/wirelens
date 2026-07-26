import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ROOT, run } from "./tooling.mjs";

const formatBytes = (bytes) => `${bytes.toLocaleString("en-US")} bytes`;
const formatMilliseconds = (value) => `${value.toFixed(2)} ms`;
const formatRatio = (value) => `${value.toFixed(2)}x`;
const formatThroughput = (value) => `${value.toFixed(1)} MB/s`;

run("corepack", ["pnpm", "run", "verify:toolchain"]);
run("corepack", ["pnpm", "run", "build:wasm"]);
run("corepack", ["pnpm", "run", "verify:contract"]);
run("corepack", ["pnpm", "run", "typecheck"]);
run("corepack", ["pnpm", "run", "build:web"]);

const results = join(ROOT, "test-results");
const jsonPath = join(results, "boundary-evidence.json");
const markdownPath = join(results, "boundary-evidence.md");
const committedMarkdownPath = join(ROOT, "EVIDENCE.md");
mkdirSync(results, { recursive: true });
run(
  "corepack",
  ["pnpm", "exec", "playwright", "test", "tests/evidence.spec.ts", "--project=chromium"],
  { env: { WIRELENS_EVIDENCE_PATH: jsonPath } },
);

const evidence = JSON.parse(readFileSync(jsonPath, "utf8"));
const denseMaxStep = Math.max(...evidence.dense.stepDurationsMs);
const repeatedWasmPeak = Math.max(...evidence.memory.repeated.wasmAfterBytes);
const repeatedWasmGrowth =
  repeatedWasmPeak - evidence.memory.repeated.wasmPlateauBaselineBytes;
const cancellationWasmGrowth = Math.max(
  0,
  Math.max(...evidence.cancellation.wasmBytes) -
    evidence.memory.repeated.wasmPlateauBaselineBytes,
);
const failureWasmGrowth = Math.max(
  0,
  Math.max(...evidence.failures.wasmBytes) - evidence.memory.repeated.wasmPlateauBaselineBytes,
);
const markdown = `# Wasm boundary evidence

Recorded ${evidence.recordedAt} in ${evidence.browserName}. The browser reported \`${evidence.environment.userAgent}\` and ${evidence.environment.hardwareConcurrency} logical processors. Fixtures are deterministic, generated in memory, and contain no captured private traffic.

> This is supported-boundary workload evidence below 500 MB. It does not satisfy or redefine
> ADR-0001's successful \`>=500 MB\` large-capture criterion; ADR-0008 and issue #55 keep that
> product-level L2/T1/M1 decision open.

This report is emitted only after the exact toolchain check, direct Cargo + \`wasm-bindgen\` production build, static binary-transport/API-signature contract check, TypeScript check, production bundle, and all assertions below pass.

## Acceptance measurements

| Measurement | Result | Limit |
| --- | ---: | ---: |
| Sparse ingest + index throughput (${formatBytes(evidence.sparse.captureBytes)}) | ${formatThroughput(evidence.sparse.megabytesPerSecond)} | >= 50 MB/s |
| Largest dense synchronous step | ${formatMilliseconds(denseMaxStep)} | <= 200 ms |
| Dense finalization checkpoint | ${formatMilliseconds(evidence.dense.finalizationDurationMs)} | <= 200 ms |
| Median queued cancellation acknowledgement | ${formatMilliseconds(evidence.cancellation.medianAcknowledgementMs)} | <= 200 ms |
| Cancellation while terminal batch is pending | ${formatMilliseconds(evidence.cancellation.terminalBatchAcknowledgementMs)} | <= 200 ms |
| Largest option-dense hostile-tail step (${evidence.hostileOptions.decodedItems.toLocaleString("en-US")} decoded items behind the checkpoint) | ${formatMilliseconds(Math.max(...evidence.hostileOptions.stepDurationsMs))} | <= 200 ms |
| Option-dense hostile-tail cancellation | ${formatMilliseconds(evidence.hostileOptions.cancellationMs)} | <= 200 ms |
| Browser agent-cluster sampled high-water growth / dense capture | ${formatRatio(evidence.memory.browser.denseSampledGrowthRatioToCapture)} | <= 2.5x |
| Wasm linear-memory sampled high-water growth / dense capture | ${formatRatio(evidence.memory.wasm.denseSampledGrowthRatioToCapture)} | <= 2.5x |
| Conservative modeled synchronous envelope / dense capture | ${formatRatio(evidence.memory.modeledSynchronousEnvelope.ratioToCapture)} | <= 2.5x |
| Retained capture + canonical index / dense capture | ${formatRatio(evidence.dense.logicalBytesRatioToCapture)} | <= 2.5x |
| Packet batch | ${formatBytes(evidence.batch.byteLength)} | <= ${formatBytes(evidence.capabilities.maxPacketBatchBytes)} |
| Packet-batch extraction + transfer | ${formatThroughput(evidence.batch.throughputMegabytesPerSecond)} | measured |
| Evidence extraction + transfer | ${formatThroughput(evidence.evidenceTransfer.throughputMegabytesPerSecond)} | measured |
| Same-size success + binary-transfer Wasm high-water growth | ${formatBytes(repeatedWasmGrowth)} | 0 bytes |
| Queued-cancellation Wasm high-water growth | ${formatBytes(cancellationWasmGrowth)} | 0 bytes |
| Fatal resource-limit Wasm high-water growth | ${formatBytes(failureWasmGrowth)} | 0 bytes |

The dense fixture contains ${evidence.dense.records.toLocaleString("en-US")} near-MTU Ethernet records with ${evidence.dense.payloadBytes.toLocaleString("en-US")} authored payload bytes each, totaling ${formatBytes(evidence.dense.captureBytes)}. Its proportional admission ceiling was ${evidence.dense.admittedPackets.toLocaleString("en-US")} packets. The sparse fixture contains ${evidence.sparse.records.toLocaleString("en-US")} large records in ${formatBytes(evidence.sparse.captureBytes)}. Both passed through an explicit \`validating\` checkpoint before a later call atomically published the dataset.

The ${formatBytes(evidence.hostileOptions.captureBytes)} PCAPNG hostile fixture contains ${evidence.hostileOptions.decodedItems.toLocaleString("en-US")} individually valid options across 513 blocks. Twelve calls each made monotonic byte progress while the cumulative ${evidence.capabilities.maxDecodedItemsPerStep.toLocaleString("en-US")}-item work checkpoint prevented decoding the remaining tail in one worker task; cancellation then returned the boundary to its exact baseline.

## Ownership and allocation accounting

This is a source-inspected allocation model corroborated by runtime detachment checks. Detachment proves transfer semantics and the ownership hand-off; JavaScript does not expose whether a browser engine performs a physical implementation copy.

| Boundary transition | Modeled copies or allocations | Evidence |
| --- | ---: | --- |
| Main thread -> worker | ${evidence.copies.inputTransferCopies} structured-clone copies | Transfer list used; source \`ArrayBuffer\` detached |
| Worker JavaScript -> Rust ownership | ${evidence.copies.jsToRustCopies} copy | Explicit admitted \`Uint8Array.copy_to\` of ${formatBytes(evidence.dense.captureBytes)} |
| Synchronous ingest peak | ${evidence.copies.fullInputAllocationsAtSynchronousPeak} full buffers | Transferred worker input plus Rust destination coexist only during the call |
| After \`beginImport\` returns | ${evidence.copies.persistentFullInputAllocationsAfterBegin} full buffer | Resource stats report exactly ${formatBytes(evidence.dense.afterBegin.transientImportInputBytes)} Rust-owned input |
| Rust packet batch -> worker JavaScript | ${evidence.copies.batchExtractionCopies} bounded copy | ${formatBytes(evidence.batch.byteLength)}, then source detached on transfer |
| Rust evidence view -> worker JavaScript | ${evidence.copies.evidenceExtractionCopies} bounded copy | ${formatBytes(evidence.evidenceTransfer.byteLength)}, then source detached on transfer |
| Worker -> main binary output | ${evidence.copies.workerOutputTransferCopies} structured-clone copies | Both transfer-detachment audits passed |

The static contract verifier rejects whole-capture JSON/text conversion; \`wholeCaptureJson\` was ${evidence.copies.wholeCaptureJson}. Rust batches move out of the registry before copying to a JavaScript-owned transferable buffer, so retained batch bytes remained zero.

## Retained and reserved bytes

| Resource | Bytes |
| --- | ---: |
| Published dense capture | ${formatBytes(evidence.dense.resident.retainedCaptureBytes)} |
| Dense packet-record arena | ${formatBytes(evidence.dense.resident.retainedPacketIndexBytes)} |
| All dense canonical indexes and strings | ${formatBytes(evidence.dense.resident.retainedIndexBytes)} |
| Dense retained logical total | ${formatBytes(evidence.dense.resident.retainedLogicalBytes)} |
| Parser-buffer upper bound after begin | ${formatBytes(evidence.dense.afterBegin.transientParserBufferBytesUpperBound)} |
| Packet-index reservation after begin | ${formatBytes(evidence.dense.afterBegin.transientPacketIndexBytesUpperBound)} |
| Auxiliary/finalization reservation after begin | ${formatBytes(evidence.dense.afterBegin.transientAuxiliaryBytesUpperBound)} |
| Total logical upper bound after begin | ${formatBytes(evidence.dense.afterBegin.totalLogicalBytesUpperBound)} |

After dense disposal, ${evidence.cancellation.samplesMs.length} queued-cancellation samples, ${evidence.failures.codes.length} fatal resource-limit samples, sparse disposal, and each of ${evidence.resources.repeated.length} same-size success/transfer sessions, all live handle counts and retained/reserved byte counters returned to the original baseline. Cancellation and fatal-error samples also stayed at or below the Wasm high-water established by the same-size successful workload. Wasm linear memory is deliberately reported as a reusable high-water allocation; it is not described as reclaimable retained capture state.

## Privacy and transfer checks

- The page was cross-origin isolated and the Wasm ran in a production \`type: "module"\` worker.
- The browser emitted ${evidence.runtimeAudit.errors.length} uncaught page, worker, or console errors during the complete evidence run.
- The test blocked external requests and observed ${evidence.privacy.externalRequests} external requests, ${evidence.privacy.captureBearingRequests} non-GET/body-bearing requests, ${evidence.privacy.postReadyRequests} HTTP requests after the worker became ready, and ${evidence.privacy.webSockets} WebSocket channels. Because every import ran after that checkpoint, no audited HTTP or WebSocket path could carry capture bytes.
- Main-to-worker input, worker-to-main batch, and worker-to-main evidence transfers all detached their source buffers. This confirms transfer/ownership semantics, not unobservable physical engine-copy behavior.
- The independently implemented worker-side batch decoder validated the returned header, descriptors, alignment, ranges, row sequence, and evidence references before transfer. The main thread performed only the constant-work header and twelve-descriptor envelope check before commit.

## Memory sampling notes

Browser memory came from \`${evidence.memory.browser.source}\`. The reported runtime number is an agent-cluster sampled high-water relative to the already-loaded, idle boundary, using samples at input creation, the validating checkpoint, and binary transfer; it is not labeled as an unsampled instantaneous peak. Wasm memory was sampled after every dense step and before and after every same-size repeated success/transfer session.

The conservative synchronous envelope is ${formatBytes(evidence.memory.modeledSynchronousEnvelope.bytes)}. It takes the maximum of the two-full-input \`beginImport\` overlap, the parser's exact retained-plus-reserved logical upper bound, and published logical state plus two bounded output buffers at the larger binary-output cap (${formatBytes(evidence.memory.modeledSynchronousEnvelope.boundedBinaryOutputBytes)}). Runtime samples, this source-inspected model, and exact logical counters are distinct evidence and none is presented as a substitute for the others.
`;
writeFileSync(markdownPath, markdown);
writeFileSync(committedMarkdownPath, markdown);
console.log(markdown);
console.log(`raw evidence: ${jsonPath}`);
console.log(`report: ${markdownPath}`);
console.log(`committed report: ${committedMarkdownPath}`);
