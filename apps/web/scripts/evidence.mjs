import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { RECOMMENDED_NEAR_CAP_TARGET_BYTES } from "../tests/support/capture-fixtures.mjs";
import { sourceTreeIdentity } from "./source-identity.mjs";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(appRoot, "../..");
const reportPath = resolve(repositoryRoot, "benchmarks/browser-ingestion/EVIDENCE.md");
const committedResultPath = resolve(repositoryRoot, "benchmarks/browser-ingestion/EVIDENCE.json");
const renderOnly = process.argv.includes("--render-only");
const checkCommitted = process.argv.includes("--check-committed");
const inputFlag = process.argv.indexOf("--input");
const inputArgument = inputFlag === -1 ? undefined : process.argv[inputFlag + 1];
if (inputFlag !== -1 && inputArgument === undefined) {
  throw new Error("--input requires a path");
}
const resultPath =
  inputArgument === undefined
    ? checkCommitted
      ? committedResultPath
      : resolve(appRoot, "test-results/browser-ingestion-evidence.json")
    : resolve(process.cwd(), inputArgument);
const outputFlag = process.argv.indexOf("--output");
const outputArgument = outputFlag === -1 ? undefined : process.argv[outputFlag + 1];
if (outputFlag !== -1 && outputArgument === undefined) {
  throw new Error("--output requires a path");
}
const outputPath =
  outputArgument === undefined ? reportPath : resolve(process.cwd(), outputArgument);

function runPnpm(script) {
  const packageManager = process.env.npm_execpath;
  const command = packageManager === undefined ? "corepack" : process.execPath;
  const args =
    packageManager === undefined ? ["pnpm", "run", script] : [packageManager, "run", script];
  const result = spawnSync(command, args, {
    cwd: appRoot,
    env: process.env,
    stdio: "inherit",
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`${script} exited with status ${result.status}`);
}

if (!renderOnly) {
  for (const script of [
    "build:wasm",
    "test:fixtures",
    "typecheck",
    "verify:privacy",
    "build:web",
    "test:browser:evidence",
  ]) {
    runPnpm(script);
  }
}

function assertEvidence(condition, message) {
  if (!condition) throw new Error(`refusing to publish evidence: ${message}`);
}

function finiteNonnegative(value) {
  return Number.isFinite(value) && value >= 0;
}

function nearlyEqual(actual, expected) {
  return (
    Number.isFinite(actual) &&
    Number.isFinite(expected) &&
    Math.abs(actual - expected) <= Math.max(1, Math.abs(expected)) * 1e-12
  );
}

const countResourceKeys = ["cursors", "datasets", "imports"];
const byteResourceKeys = [
  "currentOwnedCaptureBytes",
  "retainedBatchBytes",
  "retainedCaptureBytes",
  "retainedIndexBytes",
  "retainedLogicalBytes",
  "retainedPacketIndexBytes",
  "totalLogicalBytesUpperBound",
  "transientAuxiliaryBytesUpperBound",
  "transientImportInputBytes",
  "transientPacketIndexBytesUpperBound",
  "transientParserBufferBytesUpperBound",
];

function resourcesHaveShape(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    countResourceKeys.every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0) &&
    byteResourceKeys.every(
      (key) => typeof value[key] === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value[key]),
    )
  );
}

function resourcesAreZero(value) {
  return (
    resourcesHaveShape(value) &&
    countResourceKeys.every((key) => value[key] === 0) &&
    byteResourceKeys.every((key) => value[key] === "0")
  );
}

const result = JSON.parse(readFileSync(resultPath, "utf8"));
const currentSource = await sourceTreeIdentity();
assertEvidence(
  result.source?.sha256 === currentSource.sha256,
  `source-tree digest is stale: recorded ${result.source?.sha256 ?? "missing"}, current ${currentSource.sha256}`,
);
assertEvidence(
  /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(result.source?.baseRevision ?? "") &&
    /^[0-9a-f]{64}$/u.test(result.source?.sha256 ?? ""),
  "source identity is malformed",
);
assertEvidence(
  result.qualifyingProfile === true &&
    result.fixture?.targetBytes === RECOMMENDED_NEAR_CAP_TARGET_BYTES,
  `expected the exact ${RECOMMENDED_NEAR_CAP_TARGET_BYTES}-byte requested profile`,
);

const exactBytes = result.fixture?.exactBytes;
assertEvidence(
  Number.isSafeInteger(exactBytes) && exactBytes > 0 && exactBytes <= 256 * 1024 * 1024,
  "fixture byte length is outside the supported v1 boundary",
);
assertEvidence(
  /^[0-9a-f]{64}$/u.test(result.fixture?.manifestSha256 ?? "") &&
    Number.isSafeInteger(result.fixture?.recipe?.payloadBytes) &&
    result.fixture.recipe.payloadBytes > 0,
  "fixture identity or recipe is malformed",
);

assertEvidence(
  finiteNonnegative(result.importElapsedMs) && result.importElapsedMs > 0,
  "import duration is missing or invalid",
);
const recomputedThroughput = exactBytes / (1024 * 1024) / (result.importElapsedMs / 1_000);
assertEvidence(
  nearlyEqual(result.effectiveThroughputMibPerSecond, recomputedThroughput) &&
    recomputedThroughput >= 50,
  "throughput is inconsistent or below 50 MiB/s",
);
assertEvidence(
  Number.isSafeInteger(result.heartbeatTicks) && result.heartbeatTicks > 0,
  "the main-thread heartbeat did not advance",
);
assertEvidence(
  Array.isArray(result.longTasksOver50Ms) && result.longTasksOver50Ms.length === 0,
  "a main-thread task exceeded 50 ms",
);

const expectedCancellationPhases = [
  "reading",
  "parsing",
  "reading",
  "parsing",
  "reading",
  "parsing",
];
assertEvidence(
  JSON.stringify(result.cancellationPhases) === JSON.stringify(expectedCancellationPhases) &&
    Array.isArray(result.cancellationLatenciesMs) &&
    result.cancellationLatenciesMs.length === expectedCancellationPhases.length &&
    result.cancellationLatenciesMs.every(finiteNonnegative),
  "reading/parsing cancellation samples are incomplete or invalid",
);
const sortedCancellation = [...result.cancellationLatenciesMs].sort((left, right) => left - right);
const recomputedCancellationMedian = (sortedCancellation[2] + sortedCancellation[3]) / 2;
assertEvidence(
  nearlyEqual(result.cancellationMedianMs, recomputedCancellationMedian) &&
    recomputedCancellationMedian <= 200,
  "cancellation median is inconsistent or above 200 ms",
);

const memory = result.memory;
assertEvidence(
  typeof memory === "object" &&
    memory !== null &&
    finiteNonnegative(memory.baselineBytes) &&
    finiteNonnegative(memory.finalBytes) &&
    Array.isArray(memory.samples) &&
    memory.samples.length > 0 &&
    memory.samples.every(finiteNonnegative) &&
    Number.isSafeInteger(memory.sampleCount) &&
    memory.sampleCount === memory.samples.length,
  "memory samples are incomplete or invalid",
);
const recomputedPeakBytes = Math.max(memory.baselineBytes, memory.finalBytes, ...memory.samples);
const recomputedAttributableBytes = Math.max(0, recomputedPeakBytes - memory.baselineBytes);
const recomputedAttributableRatio = recomputedAttributableBytes / exactBytes;
assertEvidence(
  memory.peakBytes === recomputedPeakBytes &&
    memory.attributablePeakBytes === recomputedAttributableBytes &&
    nearlyEqual(memory.attributablePeakRatio, recomputedAttributableRatio) &&
    recomputedAttributableRatio <= 2.5,
  "sampled memory high-water is inconsistent or above 2.5x",
);

const modeled = memory.modeledEnvelope;
assertEvidence(
  typeof modeled === "object" &&
    modeled !== null &&
    Number.isSafeInteger(modeled.admittedReadChunkBytes) &&
    modeled.admittedReadChunkBytes > 0 &&
    modeled.admittedReadChunkBytes <= exactBytes &&
    Number.isSafeInteger(modeled.parserLogicalUpperBoundBytes) &&
    modeled.parserLogicalUpperBoundBytes >= 0,
  "modeled allocation inputs are invalid",
);
const recomputedReadAssembly = exactBytes + modeled.admittedReadChunkBytes;
const recomputedSynchronousCopy = 2 * exactBytes + modeled.admittedReadChunkBytes;
const recomputedModeledBytes = Math.max(
  recomputedReadAssembly,
  recomputedSynchronousCopy,
  modeled.parserLogicalUpperBoundBytes,
);
const recomputedModeledRatio = recomputedModeledBytes / exactBytes;
assertEvidence(
  modeled.readAssemblyPeakBytes === recomputedReadAssembly &&
    modeled.synchronousCopyPeakBytes === recomputedSynchronousCopy &&
    modeled.bytes === recomputedModeledBytes &&
    nearlyEqual(modeled.ratioToCapture, recomputedModeledRatio) &&
    recomputedModeledRatio <= 2.5,
  "modeled allocation envelope is inconsistent or above 2.5x",
);

assertEvidence(
  result.privacy?.postReadyHttpRequests === 0 &&
    result.privacy?.bodyBearingRequests === 0 &&
    result.privacy?.webSockets === 0 &&
    result.privacy?.runtimeErrors === 0,
  "network, upload, WebSocket, or runtime-error privacy gate failed",
);
assertEvidence(
  result.workerToMainBinaryBytes === 0,
  "worker returned capture bytes to the main thread",
);
assertEvidence(
  resourcesAreZero(result.baselineResources) &&
    resourcesAreZero(result.resetResources) &&
    JSON.stringify(result.resetResources) === JSON.stringify(result.baselineResources),
  "reset resources do not match the exact zero baseline",
);
assertEvidence(
  resourcesHaveShape(result.successResources) &&
    result.successResources.imports === 0 &&
    result.successResources.datasets === 1 &&
    result.successResources.cursors === 0 &&
    result.successResources.currentOwnedCaptureBytes === String(exactBytes) &&
    result.successResources.retainedCaptureBytes === String(exactBytes),
  "successful import does not retain exactly one capture dataset",
);
const exactMib = result.fixture.exactBytes / (1024 * 1024);
const cancellationSamples = result.cancellationLatenciesMs
  .map((value) => Number(value).toFixed(2))
  .join(", ");
const formatter = new Intl.NumberFormat("en-US");
const report = `# Browser-ingestion evidence

Recorded ${result.recordedAt} from the production bundle in full Chromium ${result.browserVersion}. The fixture generator created only deterministic synthetic traffic in temporary storage; its runtime manifest SHA-256 was \`${result.fixture.manifestSha256}\`.

> This is the supported v1 path at exactly ${formatter.format(result.fixture.exactBytes)} bytes (${exactMib.toFixed(2)} MiB), below the accepted 256 MiB boundary. It does not satisfy or redefine ADR-0001's successful \`>=500 MB\` path. The separate sparse 500 MiB scenario proves pre-read rejection only.

## Reference profile

| Field | Value |
| --- | --- |
| Host | ${result.environment.cpu}; ${result.environment.logicalCpus} logical CPUs; ${(result.environment.totalMemoryBytes / 1024 ** 3).toFixed(0)} GiB RAM |
| Platform | ${result.environment.platform} / ${result.environment.architecture} |
| Browser | Full Chromium ${result.browserVersion}, cross-origin isolated |
| Fixture | ${formatter.format(result.fixture.exactBytes)} bytes, ${result.fixture.recipe.payloadBytes}-byte synthetic payload records |
| Build | Pinned production Vite module-worker bundle; local Wasm asset |
| Source base revision | \`${result.source.baseRevision}\` |
| Source-tree SHA-256 | \`${result.source.sha256}\` |

## Quantitative supported-path result

| Measurement | Result | Gate | Status |
| --- | ---: | ---: | --- |
| Effective file-read + ingest + index throughput | ${result.effectiveThroughputMibPerSecond.toFixed(2)} MiB/s | >=50 MiB/s | pass |
| Main-thread long tasks over 50 ms | ${result.longTasksOver50Ms.length} | 0 | pass |
| Main-thread heartbeat ticks during import | ${result.heartbeatTicks} | >0 | pass |
| Cancellation acknowledgement samples | ${cancellationSamples} ms | reading + parsing | pass |
| Cancellation acknowledgement median | ${result.cancellationMedianMs.toFixed(2)} ms | <=200 ms | pass |
| Sampled attributable agent-cluster memory high-water | ${result.memory.attributablePeakRatio.toFixed(2)}x input | <=2.5x | pass |
| Product-path source-modeled allocation envelope | ${result.memory.modeledEnvelope.ratioToCapture.toFixed(2)}x input | <=2.5x | pass |
| Worker-to-main binary response | ${result.workerToMainBinaryBytes} bytes | <=8 MiB | pass |

Chromium memory used \`measureUserAgentSpecificMemory\` across ${result.memory.sampleCount} agent-cluster samples. Idle baseline was ${formatter.format(result.memory.baselineBytes)} bytes; sampled absolute high-water was ${formatter.format(result.memory.peakBytes)} bytes; attributable growth was ${formatter.format(result.memory.attributablePeakBytes)} bytes. Because an asynchronous sampler cannot interrupt the worker's synchronous JavaScript-to-Wasm copy, the product-path model separately takes the maximum of: read assembly (${formatter.format(result.memory.modeledEnvelope.readAssemblyPeakBytes)} bytes), the whole-input JavaScript-to-Rust overlap plus one admitted ${formatter.format(result.memory.modeledEnvelope.admittedReadChunkBytes)}-byte slice (${formatter.format(result.memory.modeledEnvelope.synchronousCopyPeakBytes)} bytes), and the sampled parser logical upper bound (${formatter.format(result.memory.modeledEnvelope.parserLogicalUpperBoundBytes)} bytes). The resulting ${formatter.format(result.memory.modeledEnvelope.bytes)}-byte envelope is ${result.memory.modeledEnvelope.ratioToCapture.toFixed(2)}x the exact input. The worker releases its chunk-assembled JavaScript input reference immediately after the admitted Wasm copy returns.

## Privacy and cleanup

| Check after worker readiness | Result | Gate |
| --- | ---: | ---: |
| HTTP(S) requests | ${result.privacy.postReadyHttpRequests} | 0 |
| Body-bearing requests | ${result.privacy.bodyBearingRequests} | 0 |
| WebSocket channels | ${result.privacy.webSockets} | 0 |
| Page, worker, or console errors | ${result.privacy.runtimeErrors} | 0 |
| Live imports after explicit reset | ${result.resetResources.imports} | 0 |
| Live datasets after explicit reset | ${result.resetResources.datasets} | 0 |
| Live cursors after explicit reset | ${result.resetResources.cursors} | 0 |
| Retained logical bytes after explicit reset | ${result.resetResources.retainedLogicalBytes} | 0 |
| Total logical upper bound after explicit reset | ${result.resetResources.totalLogicalBytesUpperBound} | 0 |

The cross-browser production suite runs with service workers allowed and asserts zero registrations, IndexedDB databases, Cache Storage entries, local-storage entries, or session-storage entries. Static privacy checks also reject those APIs in product sources. The suite patches main-realm \`File.prototype.arrayBuffer\` to throw while a valid import succeeds, proving product code reads capture bytes only in the worker. Successful import retains exactly one dataset until the user resets; success, failure, reading cancellation, parsing cancellation, and reset return every live handle and retained/reserved logical-byte counter to baseline.

## Functional acceptance matrix

The pinned Playwright suite runs in Chromium and Firefox against the production bundle and covers:

- native picker and accessible drag/drop, including multiple-file rejection and same-file reselection;
- all four classic PCAP magics and both PCAPNG byte orders;
- misleading/missing extensions and MIME types, with magic authoritative;
- empty, short, random, truncated, malformed, declared-size, option-density, and packet-density hostile inputs;
- separate monotonic file-read and Rust-parse progress;
- cancellation during file acquisition and between bounded Wasm steps;
- exact logical cleanup after success, failure, cancellation, and reset;
- zero post-ready requests, WebSockets, raw-capture persistence, or service-worker control;
- keyboard semantics, live/alert regions, terminal focus, and 320 CSS-pixel reflow.

The sparse logical ADR-0001 guard is at least 500 MiB. Browser tests observe no \`reading\` or \`parsing\` state and zero Wasm import/dataset/cursor handles before the structured \`resource_limit\` result. That result is admission evidence, not successful-import performance evidence.

## Reproduction

\`\`\`sh
cd apps/web
corepack pnpm install --frozen-lockfile
corepack pnpm run verify
WIRELENS_INGESTION_EVIDENCE_MIB=240 corepack pnpm run evidence
\`\`\`

Generated captures remain in temporary or ignored test output. The compact qualifying JSON is committed beside this report so pull-request CI can reproduce the report, recheck every gate, and reject a stale source digest. Regenerate both artifacts after any file-ingestion, worker scheduling, Wasm-boundary, fixture, or measurement change.
`;

if (checkCommitted) {
  if (readFileSync(reportPath, "utf8") !== report) {
    throw new Error("committed browser-ingestion report does not match its qualifying JSON");
  }
  process.stdout.write(
    "Committed browser-ingestion evidence is current and satisfies every gate\n",
  );
} else {
  if (!renderOnly && outputArgument === undefined) {
    writeFileSync(committedResultPath, `${JSON.stringify(result, null, 2)}\n`);
  }
  writeFileSync(outputPath, report);
  process.stdout.write(`Wrote ${outputPath}\n`);
}
