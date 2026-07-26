import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { cpus, totalmem } from "node:os";
import { join } from "node:path";

import { expect, type Page, test } from "@playwright/test";

import type { ResourceStats } from "../src/boundary/worker-contract";
import { sourceTreeIdentity } from "../scripts/source-identity.mjs";
import {
  createTemporaryFixtureDirectory,
  generateBrowserIngestionFixtures,
  MIB,
  RECOMMENDED_NEAR_CAP_TARGET_BYTES,
} from "./support/capture-fixtures.mjs";

interface EvidenceState {
  heartbeat: number;
  longTasks: number[];
  memorySamples: number[];
  resourceSampleDone: boolean;
  resourceSamples: ResourceStats[];
  samplerDone: boolean;
  sampling: boolean;
}

declare global {
  interface Window {
    __wirelensEvidence?: EvidenceState;
    __wirelensEvidenceCancellation?: { latencyMs?: number; requestedAt?: number };
  }
}

async function stats(page: Page): Promise<ResourceStats> {
  return page.evaluate(async () => {
    if (window.__wirelensDiagnostics === undefined) throw new Error("diagnostics unavailable");
    return window.__wirelensDiagnostics.resourceStats();
  });
}

function exactU64(high: number, low: number): number {
  const value = (BigInt(high) << 32n) | BigInt(low);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("resource counter exceeds the exact evidence range");
  }
  return Number(value);
}

function liveResources(value: ResourceStats) {
  const lane = (high: number, low: number): string =>
    ((BigInt(high) << 32n) | BigInt(low)).toString();
  return {
    currentOwnedCaptureBytes: lane(
      value.currentOwnedCaptureBytesHi,
      value.currentOwnedCaptureBytesLo,
    ),
    cursors: value.cursors,
    datasets: value.datasets,
    imports: value.imports,
    retainedBatchBytes: lane(value.retainedBatchBytesHi, value.retainedBatchBytesLo),
    retainedCaptureBytes: lane(value.retainedCaptureBytesHi, value.retainedCaptureBytesLo),
    retainedIndexBytes: lane(value.retainedIndexBytesHi, value.retainedIndexBytesLo),
    retainedLogicalBytes: lane(value.retainedLogicalBytesHi, value.retainedLogicalBytesLo),
    retainedPacketIndexBytes: lane(
      value.retainedPacketIndexBytesHi,
      value.retainedPacketIndexBytesLo,
    ),
    totalLogicalBytesUpperBound: lane(
      value.totalLogicalBytesUpperBoundHi,
      value.totalLogicalBytesUpperBoundLo,
    ),
    transientAuxiliaryBytesUpperBound: lane(
      value.transientAuxiliaryBytesUpperBoundHi,
      value.transientAuxiliaryBytesUpperBoundLo,
    ),
    transientImportInputBytes: lane(
      value.transientImportInputBytesHi,
      value.transientImportInputBytesLo,
    ),
    transientPacketIndexBytesUpperBound: lane(
      value.transientPacketIndexBytesUpperBoundHi,
      value.transientPacketIndexBytesUpperBoundLo,
    ),
    transientParserBufferBytesUpperBound: lane(
      value.transientParserBufferBytesUpperBoundHi,
      value.transientParserBufferBytesUpperBoundLo,
    ),
  };
}

async function measureMemory(page: Page): Promise<number> {
  return page.evaluate(async () => {
    const memoryPerformance = performance as Performance & {
      measureUserAgentSpecificMemory?: () => Promise<{ bytes: number }>;
    };
    if (memoryPerformance.measureUserAgentSpecificMemory === undefined) {
      throw new Error("measureUserAgentSpecificMemory is required for qualifying evidence");
    }
    return (await memoryPerformance.measureUserAgentSpecificMemory()).bytes;
  });
}

async function reset(page: Page): Promise<void> {
  await page.getByRole("button", { name: /open another|choose another/iu }).click();
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
}

async function armCancellation(page: Page, phase: "parsing" | "reading"): Promise<void> {
  await page.evaluate((targetPhase) => {
    const importer = document.querySelector('[data-testid="capture-importer"]');
    if (importer === null) throw new Error("importer is missing");
    window.__wirelensEvidenceCancellation = {};
    let requested = false;
    const observer = new MutationObserver(() => {
      const state = importer.getAttribute("data-import-state");
      if (!requested && state === targetPhase) {
        const button = document.querySelector<HTMLButtonElement>('[data-testid="cancel-import"]');
        if (button === null) return;
        requested = true;
        if (window.__wirelensEvidenceCancellation !== undefined) {
          window.__wirelensEvidenceCancellation.requestedAt = performance.now();
        }
        button.click();
      }
      if (requested && state === "cancelled") {
        const measurement = window.__wirelensEvidenceCancellation;
        if (measurement?.requestedAt !== undefined) {
          measurement.latencyMs = performance.now() - measurement.requestedAt;
        }
        observer.disconnect();
      }
    });
    observer.observe(importer, {
      attributeFilter: ["data-import-state"],
      attributes: true,
    });
  }, phase);
}

test("records qualifying production browser-ingestion evidence", async ({ browser, page }) => {
  test.setTimeout(180_000);
  const configuredMib = Number.parseInt(process.env.WIRELENS_INGESTION_EVIDENCE_MIB ?? "240", 10);
  if (!Number.isSafeInteger(configuredMib) || configuredMib < 8 || configuredMib > 255) {
    throw new Error("WIRELENS_INGESTION_EVIDENCE_MIB must be an integer from 8 through 255");
  }
  const targetBytes = configuredMib * MIB;
  const fixtureDirectory = await createTemporaryFixtureDirectory("wirelens-ingestion-evidence-");
  test.info().annotations.push({
    description:
      targetBytes === RECOMMENDED_NEAR_CAP_TARGET_BYTES
        ? "recommended near-cap supported-path profile"
        : "non-qualifying reduced local profile",
    type: "fixture-profile",
  });

  try {
    const { manifest } = await generateBrowserIngestionFixtures({
      includeArchitectureOversize: false,
      mediumRecords: 8,
      outputDirectory: fixtureDirectory,
      supportedLargePayloadBytes: MIB,
      supportedLargeTargetBytes: targetBytes,
    });
    const supported = manifest.fixtures.find(({ fileName }) => fileName === "supported-large.pcap");
    if (supported === undefined) throw new Error("supported evidence fixture is missing");
    const fixturePath = join(fixtureDirectory, supported.fileName);
    const manifestBytes = await readFile(join(fixtureDirectory, "fixture-manifest.json"));

    const requests: Array<{ bodyBytes: number; url: string }> = [];
    const sockets: string[] = [];
    const runtimeErrors: string[] = [];
    await page.goto("/");
    await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
    expect(await page.evaluate(() => crossOriginIsolated)).toBe(true);
    const baselineStats = await stats(page);
    const capabilities = await page.evaluate(async () => {
      if (window.__wirelensDiagnostics === undefined) throw new Error("diagnostics unavailable");
      return window.__wirelensDiagnostics.capabilities();
    });
    const source = await sourceTreeIdentity();
    page.on("request", (request) => {
      requests.push({ bodyBytes: request.postDataBuffer()?.byteLength ?? 0, url: request.url() });
    });
    page.on("websocket", (socket) => sockets.push(socket.url()));
    page.on("pageerror", (error) => runtimeErrors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") runtimeErrors.push(message.text());
    });

    const baselineMemoryBytes = await measureMemory(page);
    await page.evaluate(() => {
      const state: EvidenceState = {
        heartbeat: 0,
        longTasks: [],
        memorySamples: [],
        resourceSampleDone: false,
        resourceSamples: [],
        samplerDone: false,
        sampling: true,
      };
      window.__wirelensEvidence = state;
      const heartbeat = window.setInterval(() => {
        state.heartbeat += 1;
      }, 4);
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) state.longTasks.push(entry.duration);
      });
      observer.observe({ entryTypes: ["longtask"] });
      const memoryPerformance = performance as Performance & {
        measureUserAgentSpecificMemory: () => Promise<{ bytes: number }>;
      };
      const importer = document.querySelector('[data-testid="capture-importer"]');
      if (importer === null) throw new Error("importer is missing");
      let resourceSampleRequested = false;
      const resourceObserver = new MutationObserver(() => {
        if (
          resourceSampleRequested ||
          importer.getAttribute("data-import-state") !== "parsing" ||
          window.__wirelensDiagnostics === undefined
        ) {
          return;
        }
        resourceSampleRequested = true;
        void window.__wirelensDiagnostics
          .resourceStats()
          .then((sample) => state.resourceSamples.push(sample))
          .finally(() => {
            state.resourceSampleDone = true;
          });
      });
      resourceObserver.observe(importer, {
        attributeFilter: ["data-import-state"],
        attributes: true,
      });
      void (async () => {
        while (state.sampling) {
          state.memorySamples.push(
            (await memoryPerformance.measureUserAgentSpecificMemory()).bytes,
          );
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        window.clearInterval(heartbeat);
        observer.disconnect();
        resourceObserver.disconnect();
        state.samplerDone = true;
      })();
    });

    const startedAt = performance.now();
    await page.locator("#capture-file-input").setInputFiles(fixturePath);
    await expect(page.getByTestId("capture-importer")).toHaveAttribute(
      "data-import-state",
      "complete",
      { timeout: 120_000 },
    );
    const elapsedMs = performance.now() - startedAt;
    await expect
      .poll(() => page.evaluate(() => window.__wirelensEvidence?.resourceSampleDone ?? false))
      .toBe(true);
    await page.evaluate(() => {
      if (window.__wirelensEvidence !== undefined) window.__wirelensEvidence.sampling = false;
    });
    await expect
      .poll(() => page.evaluate(() => window.__wirelensEvidence?.samplerDone ?? false))
      .toBe(true);
    const finalMemoryBytes = await measureMemory(page);
    const measured = await page.evaluate(() => window.__wirelensEvidence);
    if (measured === undefined) throw new Error("browser measurements are missing");
    const successStats = await stats(page);

    expect(successStats.imports).toBe(0);
    expect(successStats.datasets).toBe(1);
    expect(successStats.cursors).toBe(0);
    expect(measured.heartbeat).toBeGreaterThan(0);
    expect(measured.longTasks.filter((duration) => duration > 50)).toEqual([]);
    expect(measured.resourceSamples.length).toBeGreaterThan(0);
    expect(requests).toEqual([]);
    expect(sockets).toEqual([]);
    expect(runtimeErrors).toEqual([]);

    const peakMemoryBytes = Math.max(
      baselineMemoryBytes,
      finalMemoryBytes,
      ...measured.memorySamples,
    );
    const attributablePeakBytes = Math.max(0, peakMemoryBytes - baselineMemoryBytes);
    const memoryRatio = attributablePeakBytes / supported.sizeBytes;
    const throughputMibPerSecond = supported.sizeBytes / MIB / (elapsedMs / 1_000);
    const parserLogicalUpperBoundBytes = Math.max(
      exactU64(
        successStats.totalLogicalBytesUpperBoundHi,
        successStats.totalLogicalBytesUpperBoundLo,
      ),
      ...measured.resourceSamples.map((sample) =>
        exactU64(sample.totalLogicalBytesUpperBoundHi, sample.totalLogicalBytesUpperBoundLo),
      ),
    );
    const admittedReadChunkBytes = Math.min(capabilities.readChunkBytes, supported.sizeBytes);
    const readAssemblyPeakBytes = supported.sizeBytes + admittedReadChunkBytes;
    const synchronousCopyPeakBytes = 2 * supported.sizeBytes + admittedReadChunkBytes;
    const modeledEnvelopeBytes = Math.max(
      readAssemblyPeakBytes,
      synchronousCopyPeakBytes,
      parserLogicalUpperBoundBytes,
    );
    const modeledEnvelopeRatio = modeledEnvelopeBytes / supported.sizeBytes;
    expect(throughputMibPerSecond).toBeGreaterThanOrEqual(50);
    expect(memoryRatio).toBeLessThanOrEqual(2.5);
    expect(modeledEnvelopeRatio).toBeLessThanOrEqual(2.5);
    expect(
      exactU64(
        successStats.peakTransientImportInputBytesHi,
        successStats.peakTransientImportInputBytesLo,
      ),
    ).toBe(supported.sizeBytes);
    expect(
      exactU64(successStats.peakOwnedCaptureBytesHi, successStats.peakOwnedCaptureBytesLo),
    ).toBe(supported.sizeBytes);

    await reset(page);
    const resetStats = await stats(page);
    expect(liveResources(resetStats)).toEqual(liveResources(baselineStats));

    const cancellationLatenciesMs: number[] = [];
    const cancellationPhases = [
      "reading",
      "parsing",
      "reading",
      "parsing",
      "reading",
      "parsing",
    ] as const;
    for (const phase of cancellationPhases) {
      await armCancellation(page, phase);
      await page.locator("#capture-file-input").setInputFiles(fixturePath);
      await expect(page.getByTestId("capture-importer")).toHaveAttribute(
        "data-import-state",
        "cancelled",
        { timeout: 120_000 },
      );
      const latency = await page.evaluate(() => window.__wirelensEvidenceCancellation?.latencyMs);
      if (latency === undefined) throw new Error(`${phase} cancellation was not measured`);
      cancellationLatenciesMs.push(latency);
      const cancelledStats = await stats(page);
      expect(liveResources(cancelledStats)).toEqual(liveResources(baselineStats));
      await reset(page);
    }
    const sortedCancellation = [...cancellationLatenciesMs].sort((left, right) => left - right);
    const lowerMedian = sortedCancellation[2];
    const upperMedian = sortedCancellation[3];
    if (lowerMedian === undefined || upperMedian === undefined) {
      throw new Error("six cancellation samples are required");
    }
    const cancellationMedianMs = (lowerMedian + upperMedian) / 2;
    expect(cancellationMedianMs).toBeLessThanOrEqual(200);

    const result = {
      browserVersion: browser.version(),
      baselineResources: liveResources(baselineStats),
      cancellationLatenciesMs,
      cancellationMedianMs,
      cancellationPhases,
      effectiveThroughputMibPerSecond: throughputMibPerSecond,
      environment: {
        architecture: process.arch,
        cpu: cpus()[0]?.model ?? "unknown",
        logicalCpus: cpus().length,
        platform: process.platform,
        totalMemoryBytes: totalmem(),
      },
      fixture: {
        exactBytes: supported.sizeBytes,
        manifestSha256: createHash("sha256").update(manifestBytes).digest("hex"),
        recipe: supported.recipe,
        targetBytes,
      },
      heartbeatTicks: measured.heartbeat,
      importElapsedMs: elapsedMs,
      longTasksOver50Ms: measured.longTasks.filter((duration) => duration > 50),
      memory: {
        attributablePeakBytes,
        attributablePeakRatio: memoryRatio,
        baselineBytes: baselineMemoryBytes,
        finalBytes: finalMemoryBytes,
        modeledEnvelope: {
          admittedReadChunkBytes,
          bytes: modeledEnvelopeBytes,
          parserLogicalUpperBoundBytes,
          ratioToCapture: modeledEnvelopeRatio,
          readAssemblyPeakBytes,
          synchronousCopyPeakBytes,
        },
        peakBytes: peakMemoryBytes,
        sampleCount: measured.memorySamples.length,
        samples: measured.memorySamples,
      },
      privacy: {
        bodyBearingRequests: requests.filter(({ bodyBytes }) => bodyBytes > 0).length,
        postReadyHttpRequests: requests.length,
        runtimeErrors: runtimeErrors.length,
        webSockets: sockets.length,
      },
      recordedAt: new Date().toISOString(),
      qualifyingProfile: targetBytes === RECOMMENDED_NEAR_CAP_TARGET_BYTES,
      resetResources: liveResources(resetStats),
      successResources: liveResources(successStats),
      source,
      workerToMainBinaryBytes: 0,
    };
    await mkdir("test-results", { recursive: true });
    await writeFile(
      join("test-results", "browser-ingestion-evidence.json"),
      `${JSON.stringify(result, null, 2)}\n`,
    );
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});
