import { writeFileSync } from "node:fs";

import { expect, test } from "@playwright/test";

const evidencePath = process.env.WIRELENS_EVIDENCE_PATH;

test("records bounded-work, memory, ownership, transfer, and cleanup evidence", async ({
  browserName,
  page,
}) => {
  test.skip(evidencePath === undefined, "run through `pnpm evidence` to record the report");
  test.setTimeout(120_000);

  const externalRequests: string[] = [];
  const captureBearingRequests: string[] = [];
  const postReadyRequests: string[] = [];
  const runtimeErrors: string[] = [];
  const webSockets: string[] = [];
  page.on("pageerror", (error) => {
    runtimeErrors.push(`pageerror: ${error.message}`);
  });
  page.on("console", (message) => {
    if (message.type() === "error") {
      runtimeErrors.push(`console: ${message.text()}`);
    }
  });
  page.on("websocket", (socket) => webSockets.push(socket.url()));
  let ready = false;
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const isLocal =
      url.protocol === "blob:" ||
      url.protocol === "data:" ||
      (url.hostname === "127.0.0.1" && url.port === "4174");
    if (!isLocal) {
      externalRequests.push(request.url());
      await route.abort("blockedbyclient");
      return;
    }
    if (request.method() !== "GET" || request.postData() !== null) {
      captureBearingRequests.push(request.url());
    }
    if (ready && (url.protocol === "http:" || url.protocol === "https:")) {
      postReadyRequests.push(request.url());
    }
    await route.continue();
  });

  await page.goto("/");
  await expect(page.locator("#status")).toHaveAttribute("data-state", "ready");
  ready = true;

  const evidence = await page.evaluate(async () => {
    const DENSE_RECORDS = 60_000;
    const DENSE_PAYLOAD_BYTES = 224;
    const SPARSE_RECORDS = 256;
    const SPARSE_PAYLOAD_BYTES = 60_000;
    const REPEATED_SESSIONS = 6;
    const CANCELLATION_SAMPLES = 9;
    const FAILURE_SAMPLES = 6;

    const asU64 = (high: number, low: number): bigint => (BigInt(high) << 32n) | BigInt(low);
    const median = (values: number[]): number => {
      const sorted = [...values].sort((left, right) => left - right);
      return sorted[Math.floor(sorted.length / 2)];
    };
    const nextTask = (): Promise<void> =>
      new Promise((resolve) => {
        setTimeout(resolve, 0);
      });
    const measureBrowserBytes = async (): Promise<{ bytes: number; source: string }> => {
      const memoryPerformance = performance as Performance & {
        measureUserAgentSpecificMemory?: () => Promise<{ bytes: number }>;
      };
      if (memoryPerformance.measureUserAgentSpecificMemory === undefined) {
        throw new Error(
          "qualifying boundary evidence requires measureUserAgentSpecificMemory",
        );
      }
      const result = await memoryPerformance.measureUserAgentSpecificMemory();
      return { bytes: result.bytes, source: "measureUserAgentSpecificMemory" };
    };
    const resourceSnapshot = async () => {
      const stats = await window.wirelensBoundary.resourceStats();
      return {
        currentOwnedCaptureBytes: Number(
          asU64(stats.currentOwnedCaptureBytesHi, stats.currentOwnedCaptureBytesLo),
        ),
        cursors: stats.cursors,
        datasets: stats.datasets,
        imports: stats.imports,
        peakOwnedCaptureBytes: Number(
          asU64(stats.peakOwnedCaptureBytesHi, stats.peakOwnedCaptureBytesLo),
        ),
        peakTransientImportInputBytes: Number(
          asU64(
            stats.peakTransientImportInputBytesHi,
            stats.peakTransientImportInputBytesLo,
          ),
        ),
        retainedBatchBytes: Number(
          asU64(stats.retainedBatchBytesHi, stats.retainedBatchBytesLo),
        ),
        retainedCaptureBytes: Number(
          asU64(stats.retainedCaptureBytesHi, stats.retainedCaptureBytesLo),
        ),
        retainedIndexBytes: Number(asU64(stats.retainedIndexBytesHi, stats.retainedIndexBytesLo)),
        retainedLogicalBytes: Number(
          asU64(stats.retainedLogicalBytesHi, stats.retainedLogicalBytesLo),
        ),
        retainedPacketIndexBytes: Number(
          asU64(stats.retainedPacketIndexBytesHi, stats.retainedPacketIndexBytesLo),
        ),
        totalLogicalBytesUpperBound: Number(
          asU64(stats.totalLogicalBytesUpperBoundHi, stats.totalLogicalBytesUpperBoundLo),
        ),
        transientAuxiliaryBytesUpperBound: Number(
          asU64(
            stats.transientAuxiliaryBytesUpperBoundHi,
            stats.transientAuxiliaryBytesUpperBoundLo,
          ),
        ),
        transientImportInputBytes: Number(
          asU64(stats.transientImportInputBytesHi, stats.transientImportInputBytesLo),
        ),
        transientPacketIndexBytesUpperBound: Number(
          asU64(
            stats.transientPacketIndexBytesUpperBoundHi,
            stats.transientPacketIndexBytesUpperBoundLo,
          ),
        ),
        transientParserBufferBytesUpperBound: Number(
          asU64(
            stats.transientParserBufferBytesUpperBoundHi,
            stats.transientParserBufferBytesUpperBoundLo,
          ),
        ),
      };
    };
    const liveResources = (snapshot: Awaited<ReturnType<typeof resourceSnapshot>>) => ({
      currentOwnedCaptureBytes: snapshot.currentOwnedCaptureBytes,
      cursors: snapshot.cursors,
      datasets: snapshot.datasets,
      imports: snapshot.imports,
      retainedBatchBytes: snapshot.retainedBatchBytes,
      retainedCaptureBytes: snapshot.retainedCaptureBytes,
      retainedIndexBytes: snapshot.retainedIndexBytes,
      retainedLogicalBytes: snapshot.retainedLogicalBytes,
      retainedPacketIndexBytes: snapshot.retainedPacketIndexBytes,
      totalLogicalBytesUpperBound: snapshot.totalLogicalBytesUpperBound,
      transientAuxiliaryBytesUpperBound: snapshot.transientAuxiliaryBytesUpperBound,
      transientImportInputBytes: snapshot.transientImportInputBytes,
      transientPacketIndexBytesUpperBound: snapshot.transientPacketIndexBytesUpperBound,
      transientParserBufferBytesUpperBound: snapshot.transientParserBufferBytesUpperBound,
    });
    const browserMemorySamples: Array<{ bytes: number; source: string; stage: string }> = [];
    const wasmMemorySamples: Array<{ bytes: number; stage: string }> = [];
    const sampleMemory = async (stage: string, includeBrowser = false): Promise<void> => {
      wasmMemorySamples.push({
        bytes: Number(await window.wirelensBoundary.wasmMemoryBytes()),
        stage,
      });
      if (includeBrowser) {
        browserMemorySamples.push({ ...(await measureBrowserBytes()), stage });
      }
    };
    const completeImport = async (
      handle: bigint,
      label: string,
      maxRecords: number,
      maxBytes: number,
      sampleValidatingMemory = false,
      sampleEveryStepWasm = true,
    ) => {
      const stepDurationsMs: number[] = [];
      const phases: string[] = [];
      let datasetHandle: bigint | undefined;
      let finalizationDurationMs = 0;
      let validatingCheckpoint = false;
      for (let index = 0; index < 10_000; index += 1) {
        const startedAt = performance.now();
        const step = await window.wirelensBoundary.stepImport(
          handle,
          maxRecords,
          maxBytes,
        );
        const durationMs = performance.now() - startedAt;
        stepDurationsMs.push(durationMs);
        phases.push(step.progress.phase);
        if (sampleEveryStepWasm) await sampleMemory(`${label}:step-${index + 1}`);
        if (step.state === "complete") {
          if (!validatingCheckpoint) {
            throw new Error(`${label} published without a prior validating checkpoint`);
          }
          datasetHandle = step.datasetHandle;
          finalizationDurationMs = durationMs;
          break;
        }
        if (step.progress.phase === "validating") {
          validatingCheckpoint = true;
          if (sampleValidatingMemory) await sampleMemory(`${label}:validating`, true);
        }
        await nextTask();
      }
      if (datasetHandle === undefined) throw new Error(`${label} did not complete`);
      return {
        datasetHandle,
        finalizationDurationMs,
        phases,
        stepDurationsMs,
        validatingCheckpoint,
      };
    };

    const capabilities = await window.wirelensBoundary.capabilities();
    const baselineResources = await resourceSnapshot();
    await sampleMemory("dense:baseline", true);

    let denseFixture: Uint8Array | undefined = window.wirelensFixtures.synthetic({
      payloadBytes: DENSE_PAYLOAD_BYTES,
      records: DENSE_RECORDS,
    });
    const denseCaptureBytes = denseFixture.byteLength;
    await sampleMemory("dense:input-ready", true);
    const denseStartedAt = performance.now();
    const denseBegun = await window.wirelensBoundary.beginImport(denseFixture);
    denseFixture = undefined;
    const denseAfterBegin = await resourceSnapshot();
    await sampleMemory("dense:after-begin");
    const denseImport = await completeImport(
      denseBegun.handle,
      "dense",
      capabilities.maxImportStepRecords,
      capabilities.maxImportStepBytes,
      true,
      true,
    );
    const denseDurationMs = performance.now() - denseStartedAt;
    const denseResident = await resourceSnapshot();
    await sampleMemory("dense:complete");

    const cursor = await window.wirelensBoundary.openPacketCursor(denseImport.datasetHandle);
    const batchStartedAt = performance.now();
    const pendingBatch = window.wirelensBoundary.readPacketBatch(
      cursor,
      capabilities.batchSchemaVersion,
      capabilities.maxPacketBatchRows,
      capabilities.maxPacketBatchBytes,
    );
    const measuredBatch = pendingBatch.then((result) => ({
      durationMs: performance.now() - batchStartedAt,
      result,
    }));
    const terminalCancelStartedAt = performance.now();
    const pendingTerminalCancel = window.wirelensBoundary
      .cancelImport(denseBegun.handle)
      .then((result) => ({
        acknowledgementMs: performance.now() - terminalCancelStartedAt,
        status: result.status,
      }));
    const [batchMeasurement, terminalCancel] = await Promise.all([
      measuredBatch,
      pendingTerminalCancel,
    ]);
    const batch = batchMeasurement.result;
    const batchDurationMs = batchMeasurement.durationMs;
    const batchView = new DataView(batch.bytes.buffer, batch.bytes.byteOffset, batch.bytes.byteLength);
    const batchRows = batchView.getUint32(24, true);

    const evidenceLength = Math.min(capabilities.maxEvidenceBytes, denseCaptureBytes);
    const evidenceStartedAt = performance.now();
    const evidenceBytes = await window.wirelensBoundary.readEvidence(
      denseImport.datasetHandle,
      0,
      0,
      evidenceLength,
    );
    const evidenceDurationMs = performance.now() - evidenceStartedAt;
    const denseAfterTransfers = await resourceSnapshot();
    await sampleMemory("dense:after-transfers", true);

    await window.wirelensBoundary.dispose(cursor);
    await window.wirelensBoundary.dispose(denseImport.datasetHandle);
    await window.wirelensBoundary.dispose(denseBegun.handle);
    const denseAfterCleanup = await resourceSnapshot();
    await sampleMemory("dense:after-cleanup");
    const denseMemorySampleCount = browserMemorySamples.length;
    const denseWasmMemorySampleCount = wasmMemorySamples.length;

    // The allocator has seen exactly the workload repeated below, but no larger
    // workload. Each repeat also exercises both binary transfer paths.
    const repeatedWasmPlateauBaseline = Number(await window.wirelensBoundary.wasmMemoryBytes());
    const repeatedWasmBeforeBytes: number[] = [];
    const repeatedWasmAfterBytes: number[] = [];
    const repeatedLiveResources: Array<ReturnType<typeof liveResources>> = [];
    for (let session = 0; session < REPEATED_SESSIONS; session += 1) {
      repeatedWasmBeforeBytes.push(Number(await window.wirelensBoundary.wasmMemoryBytes()));
      const begun = await window.wirelensBoundary.beginImport(
        window.wirelensFixtures.synthetic({
          payloadBytes: DENSE_PAYLOAD_BYTES,
          records: DENSE_RECORDS,
        }),
      );
      const imported = await completeImport(
        begun.handle,
        `repeat-${session + 1}`,
        capabilities.maxImportStepRecords,
        capabilities.maxImportStepBytes,
        false,
        false,
      );
      const repeatCursor = await window.wirelensBoundary.openPacketCursor(imported.datasetHandle);
      let repeatBatch: Awaited<ReturnType<typeof window.wirelensBoundary.readPacketBatch>> | undefined =
        await window.wirelensBoundary.readPacketBatch(
          repeatCursor,
          capabilities.batchSchemaVersion,
          capabilities.maxPacketBatchRows,
          capabilities.maxPacketBatchBytes,
        );
      let repeatEvidence: Awaited<ReturnType<typeof window.wirelensBoundary.readEvidence>> | undefined =
        await window.wirelensBoundary.readEvidence(
          imported.datasetHandle,
          0,
          0,
          Math.min(capabilities.maxEvidenceBytes, denseCaptureBytes),
        );
      if (!repeatBatch.workerSourceDetached || !repeatEvidence.workerSourceDetached) {
        throw new Error("repeated binary transfer did not detach its worker source");
      }
      repeatBatch = undefined;
      repeatEvidence = undefined;
      await window.wirelensBoundary.dispose(repeatCursor);
      await window.wirelensBoundary.dispose(imported.datasetHandle);
      await window.wirelensBoundary.dispose(begun.handle);
      const resources = await resourceSnapshot();
      repeatedLiveResources.push(liveResources(resources));
      repeatedWasmAfterBytes.push(Number(await window.wirelensBoundary.wasmMemoryBytes()));
    }

    const cancellationDurationsMs: number[] = [];
    const cancellationStepDurationsMs: number[] = [];
    const cancellationStatuses: string[] = [];
    const cancellationStepPhases: string[] = [];
    const cancellationLiveResources: Array<ReturnType<typeof liveResources>> = [];
    const cancellationWasmBytes: number[] = [];
    for (let sample = 0; sample < CANCELLATION_SAMPLES; sample += 1) {
      const candidate = await window.wirelensBoundary.beginImport(
        window.wirelensFixtures.synthetic({
          payloadBytes: DENSE_PAYLOAD_BYTES,
          records: DENSE_RECORDS,
        }),
      );
      const stepStartedAt = performance.now();
      const queuedStep = window.wirelensBoundary.stepImport(
        candidate.handle,
        Math.min(4_096, capabilities.maxImportStepRecords),
        capabilities.maxImportStepBytes,
      );
      const cancellationStartedAt = performance.now();
      const queuedCancellation = window.wirelensBoundary
        .cancelImport(candidate.handle)
        .then((result) => {
          cancellationDurationsMs.push(performance.now() - cancellationStartedAt);
          return result;
        });
      const [step, cancellation] = await Promise.all([queuedStep, queuedCancellation]);
      cancellationStepDurationsMs.push(performance.now() - stepStartedAt);
      cancellationStepPhases.push(step.progress.phase);
      cancellationStatuses.push(cancellation.status);
      cancellationLiveResources.push(liveResources(await resourceSnapshot()));
      cancellationWasmBytes.push(Number(await window.wirelensBoundary.wasmMemoryBytes()));
    }
    const afterCancellation = await resourceSnapshot();

    const failureCodes: string[] = [];
    const failureLiveResources: Array<ReturnType<typeof liveResources>> = [];
    const failureWasmBytes: number[] = [];
    for (let sample = 0; sample < FAILURE_SAMPLES; sample += 1) {
      const failing = await window.wirelensBoundary.beginImport(
        window.wirelensFixtures.synthetic({ payloadBytes: 0, records: 1_200 }),
      );
      try {
        await window.wirelensBoundary.stepImport(
          failing.handle,
          capabilities.maxImportStepRecords,
          capabilities.maxImportStepBytes,
        );
        throw new Error("resource-limit fixture unexpectedly imported");
      } catch (error) {
        failureCodes.push((error as Error & { code?: string }).code ?? "");
      }
      failureLiveResources.push(liveResources(await resourceSnapshot()));
      failureWasmBytes.push(Number(await window.wirelensBoundary.wasmMemoryBytes()));
    }

    let hostileFixture: Uint8Array | undefined = window.wirelensFixtures.optionDensePcapng({
      blocks: 513,
      itemsPerBlock: capabilities.maxDecodedItemsPerBlock,
    });
    const hostileCaptureBytes = hostileFixture.byteLength;
    const hostileDecodedItems = 513 * capabilities.maxDecodedItemsPerBlock;
    const hostileBegun = await window.wirelensBoundary.beginImport(hostileFixture);
    hostileFixture = undefined;
    const hostileStepDurationsMs: number[] = [];
    const hostileConsumedBytes: string[] = [];
    for (let stepIndex = 0; stepIndex < 12; stepIndex += 1) {
      const startedAt = performance.now();
      const step = await window.wirelensBoundary.stepImport(
        hostileBegun.handle,
        capabilities.maxImportStepRecords,
        capabilities.maxImportStepBytes,
      );
      hostileStepDurationsMs.push(performance.now() - startedAt);
      hostileConsumedBytes.push(
        asU64(step.progress.bytesConsumedHi, step.progress.bytesConsumedLo).toString(),
      );
      if (step.state !== "in_progress") {
        throw new Error("hostile option tail unexpectedly reached a terminal state");
      }
      await nextTask();
    }
    const hostileCancellationStartedAt = performance.now();
    const hostileCancellation = await window.wirelensBoundary.cancelImport(hostileBegun.handle);
    const hostileCancellationMs = performance.now() - hostileCancellationStartedAt;
    const afterHostileCancellation = await resourceSnapshot();

    let sparseFixture: Uint8Array | undefined = window.wirelensFixtures.synthetic({
      payloadBytes: SPARSE_PAYLOAD_BYTES,
      records: SPARSE_RECORDS,
    });
    const sparseCaptureBytes = sparseFixture.byteLength;
    const sparseStartedAt = performance.now();
    const sparseBegun = await window.wirelensBoundary.beginImport(sparseFixture);
    sparseFixture = undefined;
    const sparseImport = await completeImport(
      sparseBegun.handle,
      "sparse",
      capabilities.maxImportStepRecords,
      capabilities.maxImportStepBytes,
      false,
      false,
    );
    const sparseDurationMs = performance.now() - sparseStartedAt;
    await window.wirelensBoundary.dispose(sparseImport.datasetHandle);
    await window.wirelensBoundary.dispose(sparseBegun.handle);
    const afterSparseCleanup = await resourceSnapshot();
    const finalResources = await resourceSnapshot();
    await sampleMemory("final", true);

    const denseBrowserSamples = browserMemorySamples.slice(0, denseMemorySampleCount);
    const denseWasmSamples = wasmMemorySamples.slice(0, denseWasmMemorySampleCount);
    const denseBrowserBaseline = denseBrowserSamples[0].bytes;
    const denseWasmBaseline = denseWasmSamples[0].bytes;
    const denseBrowserPeak = Math.max(...denseBrowserSamples.map(({ bytes }) => bytes));
    const denseWasmPeak = Math.max(...denseWasmSamples.map(({ bytes }) => bytes));
    const admittedDensePackets = Math.min(
      capabilities.maxPackets,
      capabilities.packetAdmissionBase +
        Math.floor(denseCaptureBytes / capabilities.packetAdmissionBytesPerPacket),
    );
    const boundedBinaryOutputBytes = Math.max(
      capabilities.maxPacketBatchBytes,
      capabilities.maxEvidenceBytes,
    );
    const modeledSynchronousHighWaterBytes = Math.max(
      2 * denseCaptureBytes,
      denseAfterBegin.totalLogicalBytesUpperBound,
      denseResident.retainedLogicalBytes + 2 * boundedBinaryOutputBytes,
    );

    return {
      batch: {
        byteLength: batch.bytes.byteLength,
        durationMs: batchDurationMs,
        rows: batchRows,
        throughputMegabytesPerSecond:
          batch.bytes.byteLength / 1_000_000 / (batchDurationMs / 1_000),
        workerTransferDetached: batch.workerSourceDetached,
      },
      cancellation: {
        allStatuses: cancellationStatuses,
        liveResources: cancellationLiveResources,
        medianAcknowledgementMs: median(cancellationDurationsMs),
        samplesMs: cancellationDurationsMs,
        stepDurationsMs: cancellationStepDurationsMs,
        stepPhases: cancellationStepPhases,
        terminalBatchAcknowledgementMs: terminalCancel.acknowledgementMs,
        terminalBatchStatus: terminalCancel.status,
        wasmBytes: cancellationWasmBytes,
      },
      capabilities,
      copies: {
        basis:
          "source-inspected allocation model plus runtime transfer detachment; physical engine copies are not observable",
        batchExtractionCopies: 1,
        evidenceExtractionCopies: 1,
        fullInputAllocationsAtSynchronousPeak: 2,
        inputTransferCopies: 0,
        jsToRustCopies: 1,
        persistentFullInputAllocationsAfterBegin: 1,
        wholeCaptureJson: false,
        workerOutputTransferCopies: 0,
      },
      crossOriginIsolated,
      dense: {
        admittedPackets: admittedDensePackets,
        afterBegin: denseAfterBegin,
        afterCleanup: denseAfterCleanup,
        afterTransfers: denseAfterTransfers,
        captureBytes: denseCaptureBytes,
        durationMs: denseDurationMs,
        finalizationDurationMs: denseImport.finalizationDurationMs,
        inputDetached: denseBegun.inputDetached,
        logicalBytesRatioToCapture: denseResident.retainedLogicalBytes / denseCaptureBytes,
        records: DENSE_RECORDS,
        resident: denseResident,
        stepDurationsMs: denseImport.stepDurationsMs,
        validatingCheckpoint: denseImport.validatingCheckpoint,
      },
      environment: {
        hardwareConcurrency: navigator.hardwareConcurrency,
        userAgent: navigator.userAgent,
      },
      evidenceTransfer: {
        byteLength: evidenceBytes.bytes.byteLength,
        durationMs: evidenceDurationMs,
        throughputMegabytesPerSecond:
          evidenceBytes.bytes.byteLength / 1_000_000 / (evidenceDurationMs / 1_000),
        workerTransferDetached: evidenceBytes.workerSourceDetached,
      },
      failures: {
        codes: failureCodes,
        liveResources: failureLiveResources,
        wasmBytes: failureWasmBytes,
      },
      hostileOptions: {
        afterCancellation: liveResources(afterHostileCancellation),
        cancellationMs: hostileCancellationMs,
        cancellationStatus: hostileCancellation.status,
        captureBytes: hostileCaptureBytes,
        decodedItems: hostileDecodedItems,
        stepConsumedBytes: hostileConsumedBytes,
        stepDurationsMs: hostileStepDurationsMs,
      },
      memory: {
        browser: {
          denseBaselineBytes: denseBrowserBaseline,
          denseSampledGrowthRatioToCapture:
            Math.max(0, denseBrowserPeak - denseBrowserBaseline) / denseCaptureBytes,
          denseSampledHighWaterBytes: denseBrowserPeak,
          samples: browserMemorySamples,
          source: denseBrowserSamples[0].source,
        },
        modeledSynchronousEnvelope: {
          boundedBinaryOutputBytes,
          bytes: modeledSynchronousHighWaterBytes,
          ratioToCapture: modeledSynchronousHighWaterBytes / denseCaptureBytes,
        },
        repeated: {
          wasmAfterBytes: repeatedWasmAfterBytes,
          wasmBeforeBytes: repeatedWasmBeforeBytes,
          wasmPlateauBaselineBytes: repeatedWasmPlateauBaseline,
        },
        wasm: {
          denseBaselineBytes: denseWasmBaseline,
          denseSampledGrowthRatioToCapture:
            Math.max(0, denseWasmPeak - denseWasmBaseline) / denseCaptureBytes,
          denseSampledHighWaterBytes: denseWasmPeak,
          samples: wasmMemorySamples,
        },
      },
      resources: {
        afterCancellation: liveResources(afterCancellation),
        afterSparseCleanup: liveResources(afterSparseCleanup),
        baseline: liveResources(baselineResources),
        final: liveResources(finalResources),
        repeated: repeatedLiveResources,
      },
      sparse: {
        captureBytes: sparseCaptureBytes,
        durationMs: sparseDurationMs,
        finalizationDurationMs: sparseImport.finalizationDurationMs,
        inputDetached: sparseBegun.inputDetached,
        megabytesPerSecond: sparseCaptureBytes / 1_000_000 / (sparseDurationMs / 1_000),
        records: SPARSE_RECORDS,
        stepDurationsMs: sparseImport.stepDurationsMs,
        validatingCheckpoint: sparseImport.validatingCheckpoint,
      },
    };
  });

  expect(externalRequests).toEqual([]);
  expect(captureBearingRequests).toEqual([]);
  expect(postReadyRequests).toEqual([]);
  expect(runtimeErrors).toEqual([]);
  expect(webSockets).toEqual([]);
  expect(evidence.crossOriginIsolated).toBe(true);
  const privacy = {
    captureBearingRequests: captureBearingRequests.length,
    externalRequests: externalRequests.length,
    postReadyRequests: postReadyRequests.length,
    webSockets: webSockets.length,
  };
  expect(privacy).toEqual({
    captureBearingRequests: 0,
    externalRequests: 0,
    postReadyRequests: 0,
    webSockets: 0,
  });
  const runtimeAudit = { errors: runtimeErrors };

  expect(evidence.capabilities.maxBlockBytes).toBeLessThanOrEqual(
    evidence.capabilities.maxImportStepBytes,
  );
  expect(evidence.capabilities.maxDecodedItemsPerBlock).toBeLessThanOrEqual(
    evidence.capabilities.maxDecodedItemsPerStep,
  );
  expect(evidence.capabilities.maxPacketBatchBytes).toBeLessThanOrEqual(8 * 1024 * 1024);
  expect(evidence.capabilities.maxTotalCaptureBytes).toBeLessThanOrEqual(
    evidence.capabilities.maxTotalLogicalBytes,
  );
  expect(evidence.dense.records).toBeLessThanOrEqual(evidence.dense.admittedPackets);

  expect(evidence.dense.inputDetached).toBe(true);
  expect(evidence.dense.validatingCheckpoint).toBe(true);
  expect(evidence.dense.finalizationDurationMs).toBeLessThanOrEqual(200);
  expect(Math.max(...evidence.dense.stepDurationsMs)).toBeLessThanOrEqual(200);
  expect(evidence.dense.afterBegin.transientImportInputBytes).toBe(evidence.dense.captureBytes);
  expect(evidence.dense.afterBegin.currentOwnedCaptureBytes).toBe(evidence.dense.captureBytes);
  expect(evidence.dense.resident.retainedCaptureBytes).toBe(evidence.dense.captureBytes);
  expect(evidence.dense.resident.transientImportInputBytes).toBe(0);
  expect(evidence.dense.resident.retainedIndexBytes).toBeGreaterThan(0);
  expect(evidence.dense.resident.retainedLogicalBytes).toBe(
    evidence.dense.captureBytes + evidence.dense.resident.retainedIndexBytes,
  );
  expect(evidence.dense.logicalBytesRatioToCapture).toBeLessThanOrEqual(2.5);
  expect(evidence.dense.afterTransfers.retainedBatchBytes).toBe(0);

  expect(evidence.copies).toEqual({
    basis:
      "source-inspected allocation model plus runtime transfer detachment; physical engine copies are not observable",
    batchExtractionCopies: 1,
    evidenceExtractionCopies: 1,
    fullInputAllocationsAtSynchronousPeak: 2,
    inputTransferCopies: 0,
    jsToRustCopies: 1,
    persistentFullInputAllocationsAfterBegin: 1,
    wholeCaptureJson: false,
    workerOutputTransferCopies: 0,
  });
  expect(evidence.batch.byteLength).toBeLessThanOrEqual(
    evidence.capabilities.maxPacketBatchBytes,
  );
  expect(evidence.batch.workerTransferDetached).toBe(true);
  expect(evidence.evidenceTransfer.byteLength).toBe(evidence.capabilities.maxEvidenceBytes);
  expect(evidence.evidenceTransfer.workerTransferDetached).toBe(true);

  expect(evidence.cancellation.allStatuses).toEqual(Array(9).fill("cancelled"));
  expect(evidence.cancellation.stepPhases).toEqual(Array(9).fill("parsing"));
  expect(evidence.cancellation.medianAcknowledgementMs).toBeLessThanOrEqual(200);
  expect(evidence.cancellation.terminalBatchStatus).toBe("already_terminal");
  expect(evidence.cancellation.terminalBatchAcknowledgementMs).toBeLessThanOrEqual(200);
  expect(evidence.failures.codes).toEqual(Array(6).fill("resource_limit"));
  expect(evidence.hostileOptions.decodedItems).toBeGreaterThan(2_000_000);
  expect(evidence.hostileOptions.cancellationStatus).toBe("cancelled");
  expect(evidence.hostileOptions.cancellationMs).toBeLessThanOrEqual(200);
  expect(Math.max(...evidence.hostileOptions.stepDurationsMs)).toBeLessThanOrEqual(200);
  for (let index = 1; index < evidence.hostileOptions.stepConsumedBytes.length; index += 1) {
    expect(BigInt(evidence.hostileOptions.stepConsumedBytes[index])).toBeGreaterThan(
      BigInt(evidence.hostileOptions.stepConsumedBytes[index - 1]),
    );
  }

  expect(evidence.sparse.inputDetached).toBe(true);
  expect(evidence.sparse.validatingCheckpoint).toBe(true);
  expect(evidence.sparse.finalizationDurationMs).toBeLessThanOrEqual(200);
  expect(evidence.sparse.megabytesPerSecond).toBeGreaterThanOrEqual(50);
  expect(Math.max(...evidence.sparse.stepDurationsMs)).toBeLessThanOrEqual(200);

  expect(evidence.memory.browser.denseBaselineBytes).toBeGreaterThan(0);
  expect(evidence.memory.browser.denseSampledGrowthRatioToCapture).toBeLessThanOrEqual(2.5);
  expect(evidence.memory.wasm.denseSampledGrowthRatioToCapture).toBeLessThanOrEqual(2.5);
  expect(evidence.memory.modeledSynchronousEnvelope.ratioToCapture).toBeLessThanOrEqual(2.5);
  expect(Math.max(...evidence.memory.repeated.wasmAfterBytes)).toBeLessThanOrEqual(
    evidence.memory.repeated.wasmPlateauBaselineBytes,
  );
  expect(Math.max(...evidence.cancellation.wasmBytes)).toBeLessThanOrEqual(
    evidence.memory.repeated.wasmPlateauBaselineBytes,
  );
  expect(Math.max(...evidence.failures.wasmBytes)).toBeLessThanOrEqual(
    evidence.memory.repeated.wasmPlateauBaselineBytes,
  );
  for (const bytes of evidence.memory.repeated.wasmBeforeBytes) {
    expect(bytes).toBeLessThanOrEqual(evidence.memory.repeated.wasmPlateauBaselineBytes);
  }
  for (const resources of evidence.resources.repeated) {
    expect(resources).toEqual(evidence.resources.baseline);
  }
  for (const resources of evidence.cancellation.liveResources) {
    expect(resources).toEqual(evidence.resources.baseline);
  }
  for (const resources of evidence.failures.liveResources) {
    expect(resources).toEqual(evidence.resources.baseline);
  }
  expect(evidence.hostileOptions.afterCancellation).toEqual(evidence.resources.baseline);
  expect(evidence.resources.afterCancellation).toEqual(evidence.resources.baseline);
  expect(evidence.resources.afterSparseCleanup).toEqual(evidence.resources.baseline);
  expect(evidence.resources.final).toEqual(evidence.resources.baseline);

  writeFileSync(
    evidencePath as string,
    `${JSON.stringify(
      { browserName, recordedAt: new Date().toISOString(), ...evidence, privacy, runtimeAudit },
      null,
      2,
    )}\n`,
  );
});
