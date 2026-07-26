import { expect, test, type Page } from "@playwright/test";

import type { BoundaryFailure } from "../web/worker-contract";

interface NetworkAudit {
  captureBearingRequests: string[];
  consoleErrors: string[];
  externalRequests: string[];
  pageErrors: string[];
  postReadyRequests: string[];
  ready: boolean;
  wasmRequests: string[];
  webSockets: string[];
}

const networkAudits = new WeakMap<Page, NetworkAudit>();

test.beforeEach(async ({ page }) => {
  const audit: NetworkAudit = {
    captureBearingRequests: [],
    consoleErrors: [],
    externalRequests: [],
    pageErrors: [],
    postReadyRequests: [],
    ready: false,
    wasmRequests: [],
    webSockets: [],
  };
  networkAudits.set(page, audit);
  page.on("console", (message) => {
    if (message.type() === "error") audit.consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => audit.pageErrors.push(error.message));
  page.on("websocket", (socket) => audit.webSockets.push(socket.url()));
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const isLocal =
      url.protocol === "blob:" ||
      url.protocol === "data:" ||
      (url.hostname === "127.0.0.1" && url.port === "4174");
    if (!isLocal) {
      audit.externalRequests.push(request.url());
      await route.abort("blockedbyclient");
      return;
    }
    if (request.method() !== "GET" || request.postData() !== null) {
      audit.captureBearingRequests.push(request.url());
    }
    if (audit.ready && (url.protocol === "http:" || url.protocol === "https:")) {
      audit.postReadyRequests.push(request.url());
    }
    if (url.pathname.endsWith(".wasm")) audit.wasmRequests.push(request.url());
    await route.continue();
  });
});

test.afterEach(async ({ page }) => {
  const audit = networkAudits.get(page);
  expect(audit, "network audit was installed").toBeDefined();
  expect(audit?.externalRequests).toEqual([]);
  expect(audit?.captureBearingRequests).toEqual([]);
  expect(audit?.postReadyRequests).toEqual([]);
  expect(audit?.pageErrors, "behavioral test emitted no page errors").toEqual([]);
  expect(audit?.consoleErrors, "expected protocol failures stayed off console.error").toEqual([]);
  expect(audit?.webSockets, "the offline boundary opened no WebSockets").toEqual([]);
});

async function openHarness(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#status")).toHaveAttribute("data-state", "ready");
  const audit = networkAudits.get(page);
  if (audit !== undefined) audit.ready = true;
}

test("loads the versioned boundary in a production module worker without external traffic", async ({
  page,
}) => {
  await openHarness(page);
  const metadata = await page.evaluate(() => window.wirelensBoundary.metadata());
  expect(metadata.apiVersion).toBe(1);
  expect(metadata.batchSchemaVersion).toBe(1);
  expect(metadata.capabilities.apiVersion).toBe(metadata.apiVersion);
  expect(metadata.capabilities.batchSchemaVersion).toBe(metadata.batchSchemaVersion);
  expect(metadata.capabilities).toMatchObject({
    decodedArenaAdmissionRule:
      "min(requestedTotal, globalTotal, max(arenaBase, ceil(captureBytes / admissionBytesPerItem)))",
    decodedFieldAdmissionBase: 25 * 1_024,
    decodedFieldAdmissionBytesPerItem: 63,
    decodedLayerAdmissionBase: 4 * 1_024,
    decodedLayerAdmissionBytesPerItem: 250,
    fieldChildAdmissionBase: 21 * 1_024,
    fieldChildAdmissionBytesPerItem: 84,
    maxBlockBytes: 4 * 1024 * 1024,
    maxCaptureBytes: 256 * 1024 * 1024,
    maxDatasetHandles: 1_024,
    maxDecodedItemsPerBlock: 4_096,
    maxDecodedItemsPerStep: 4_096,
    maxDiagnostics: 1_024,
    maxFieldChildren: 1_048_576,
    maxFieldChildrenPerPacket: 2_048,
    maxFields: 1_048_576,
    maxFieldsPerPacket: 1_024,
    maxImportHandles: 16,
    maxInterfaces: 16_384,
    maxInternedStringBytes: 256 * 1024,
    maxLayers: 393_216,
    maxLayersPerPacket: 32,
    maxPacketCursorHandles: 65_536,
    maxSections: 1_024,
    maxTotalCaptureBytes: 384 * 1024 * 1024,
    maxTotalLogicalBytes: 512 * 1024 * 1024,
    packetAdmissionBase: 1_024,
    packetAdmissionBytesPerPacket: 256,
  });
  expect(metadata.capabilities.maxPacketBatchBytes).toBeLessThanOrEqual(8 * 1024 * 1024);
  expect(metadata.capabilities.maxPackets).toBeLessThanOrEqual(1_000_000);
  expect(metadata.workerContext).toBe("DedicatedWorkerGlobalScope");
  expect(networkAudits.get(page)?.wasmRequests).toHaveLength(1);

  const compatibility = await page.evaluate(async () => {
    let errorCode = "";
    try {
      await window.wirelensBoundary.metadata(2);
    } catch (error) {
      errorCode = (error as Error & { code?: string }).code ?? "";
    }
    return { errorCode, stats: await window.wirelensBoundary.resourceStats() };
  });
  expect(compatibility.errorCode).toBe("unsupported_version");
  expect(compatibility.stats.imports).toBe(0);
  expect(compatibility.stats.datasets).toBe(0);
  expect(compatibility.stats.cursors).toBe(0);

  const unknown = await page.evaluate(async () => {
    const worker = window.wirelensBoundary.worker;
    const requestId = 2_000_000_001;
    const response = new Promise<Record<string, unknown>>((resolve) => {
      const listener = (event: MessageEvent<unknown>): void => {
        if (
          typeof event.data === "object" &&
          event.data !== null &&
          (event.data as { requestId?: unknown }).requestId === requestId
        ) {
          worker.removeEventListener("message", listener);
          resolve(event.data as Record<string, unknown>);
        }
      };
      worker.addEventListener("message", listener);
    });
    worker.postMessage({ apiVersion: 1, operation: "unknown_operation", requestId });
    return response;
  });
  expect(unknown).toMatchObject({
    apiVersion: 1,
    error: { code: "invalid_argument" },
    kind: "error",
    operation: "unknown_operation",
    requestId: 2_000_000_001,
    status: "error",
  });

  const malformedEnvelope = await page.evaluate(async () => {
    const worker = window.wirelensBoundary.worker;
    const requestId = 2_000_000_002;
    const response = new Promise<Record<string, unknown>>((resolve) => {
      const listener = (event: MessageEvent<unknown>): void => {
        if (
          typeof event.data === "object" &&
          event.data !== null &&
          (event.data as { requestId?: unknown }).requestId === requestId
        ) {
          worker.removeEventListener("message", listener);
          resolve(event.data as Record<string, unknown>);
        }
      };
      worker.addEventListener("message", listener);
    });
    worker.postMessage({ apiVersion: 1, requestId });
    return response;
  });
  expect(malformedEnvelope).toMatchObject({
    apiVersion: 1,
    error: { code: "invalid_argument" },
    kind: "error",
    operation: "invalid_request",
    requestId: 2_000_000_002,
    status: "error",
  });
});

test("imports in bounded steps with monotonic exact progress and transferable batches", async ({
  page,
}) => {
  await openHarness(page);
  const result = await page.evaluate(async () => {
    const bytes = window.wirelensFixtures.synthetic({ payloadBytes: 80, records: 96 });
    const originalLength = bytes.byteLength;
    const begun = await window.wirelensBoundary.beginImport(bytes);
    const progress: Array<{ bytes: string; records: string; state: string }> = [];
    let datasetHandle: bigint | undefined;
    for (let steps = 0; steps < 1_000; steps += 1) {
      const step = await window.wirelensBoundary.stepImport(begun.handle, 7, 4_096);
      const consumed = (BigInt(step.progress.bytesConsumedHi) << 32n) |
        BigInt(step.progress.bytesConsumedLo);
      const records = (BigInt(step.progress.recordsHi) << 32n) |
        BigInt(step.progress.recordsLo);
      progress.push({ bytes: consumed.toString(), records: records.toString(), state: step.state });
      if (step.state === "complete") {
        datasetHandle = step.datasetHandle;
        break;
      }
    }
    if (datasetHandle === undefined) throw new Error("import did not complete");

    const terminalCancellation = await window.wirelensBoundary.cancelImport(begun.handle);
    const cursor = await window.wirelensBoundary.openPacketCursor(datasetHandle);
    let mismatchCode = "";
    try {
      await window.wirelensBoundary.readPacketBatch(cursor, 2, 5, 4_096);
    } catch (error) {
      mismatchCode = (error as Error & { code?: string }).code ?? "";
    }
    const batch = await window.wirelensBoundary.readPacketBatch(cursor, 1, 5, 4_096);
    const header = new DataView(batch.bytes.buffer, batch.bytes.byteOffset, batch.bytes.byteLength);
    const evidence = await window.wirelensBoundary.readEvidence(datasetHandle, 0, 40, 14);
    const stats = await window.wirelensBoundary.resourceStats();
    const memory = await window.wirelensBoundary.wasmMemoryBytes();
    return {
      batchByteLength: batch.bytes.byteLength,
      batchMagic: String.fromCharCode(...batch.bytes.slice(0, 8)),
      batchRows: header.getUint32(24, true),
      batchStartRow: header.getBigUint64(40, true).toString(),
      evidence: Array.from(evidence.bytes),
      evidenceSourceDetached: evidence.workerSourceDetached,
      inputDetached: begun.inputDetached,
      memory: memory.toString(),
      mismatchCode,
      originalLength,
      progress,
      stats,
      terminalCancellation,
      workerSourceDetached: batch.workerSourceDetached,
    };
  });

  expect(result.inputDetached).toBe(true);
  expect(result.workerSourceDetached).toBe(true);
  expect(result.evidenceSourceDetached).toBe(true);
  expect(result.progress.length).toBeGreaterThan(1);
  expect(result.progress.at(-1)?.state).toBe("complete");
  for (let index = 1; index < result.progress.length; index += 1) {
    expect(BigInt(result.progress[index].bytes)).toBeGreaterThanOrEqual(
      BigInt(result.progress[index - 1].bytes),
    );
    expect(BigInt(result.progress[index].records)).toBeGreaterThanOrEqual(
      BigInt(result.progress[index - 1].records),
    );
  }
  expect(result.terminalCancellation.status).toBe("already_terminal");
  expect(result.mismatchCode).toBe("unsupported_version");
  expect(result.batchByteLength).toBeLessThanOrEqual(4_096);
  expect(result.batchByteLength).toBeLessThanOrEqual(8 * 1024 * 1024);
  expect(result.batchMagic).toBe("WLPKTB01");
  expect(result.batchRows).toBe(5);
  expect(result.batchStartRow).toBe("0");
  expect(result.evidence).toEqual([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x88, 0xb5]);
  expect(BigInt(result.memory)).toBeGreaterThan(0n);
  expect(result.stats.retainedBatchBytesHi).toBe(0);
  expect(result.stats.retainedBatchBytesLo).toBe(0);
  expect(result.stats.retainedCaptureBytesLo).toBe(result.originalLength);
  expect(result.stats.transientImportInputBytesHi).toBe(0);
  expect(result.stats.transientImportInputBytesLo).toBe(0);
});

test("cancellation is deterministic before, between, and after terminal work", async ({ page }) => {
  await openHarness(page);
  const result = await page.evaluate(async () => {
    const before = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ records: 8 }),
    );
    const beforeCancel = await window.wirelensBoundary.cancelImport(before.handle);
    let afterCancelCode = "";
    try {
      await window.wirelensBoundary.stepImport(before.handle, 1, 1_024);
    } catch (error) {
      afterCancelCode = (error as Error & { code?: string }).code ?? "";
    }

    const between = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ records: 128 }),
    );
    let afterReuseCode = "";
    try {
      await window.wirelensBoundary.stepImport(before.handle, 1, 1_024);
    } catch (error) {
      afterReuseCode = (error as Error & { code?: string }).code ?? "";
    }
    const queuedStep = window.wirelensBoundary.stepImport(between.handle, 1, 1_024);
    const cancelQueuedAt = performance.now();
    const queuedCancel = window.wirelensBoundary.cancelImport(between.handle);
    const [firstStep, betweenCancel] = await Promise.all([queuedStep, queuedCancel]);
    const queuedCancellationMs = performance.now() - cancelQueuedAt;

    const terminal = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ records: 12 }),
    );
    let complete: Awaited<ReturnType<typeof window.wirelensBoundary.stepImport>> | undefined;
    for (let index = 0; index < 100; index += 1) {
      complete = await window.wirelensBoundary.stepImport(terminal.handle, 4, 4_096);
      if (complete.state === "complete") break;
    }
    if (complete?.datasetHandle === undefined) throw new Error("terminal import did not publish");
    const terminalCancel = await window.wirelensBoundary.cancelImport(terminal.handle);
    const cursor = await window.wirelensBoundary.openPacketCursor(complete.datasetHandle);
    const pendingBatch = window.wirelensBoundary.readPacketBatch(cursor, 1, 2, 4_096);
    const pendingTerminalCancel = window.wirelensBoundary.cancelImport(terminal.handle);
    const [batch, postBatchCancel] = await Promise.all([pendingBatch, pendingTerminalCancel]);
    await window.wirelensBoundary.dispose(complete.datasetHandle);

    return {
      afterCancelCode,
      afterReuseCode,
      beforeCancel,
      betweenCancel,
      firstStepState: firstStep.state,
      batchDetached: batch.workerSourceDetached,
      postBatchCancel,
      queuedCancellationMs,
      stats: await window.wirelensBoundary.resourceStats(),
      terminalCancel,
    };
  });
  expect(result.beforeCancel.status).toBe("cancelled");
  expect(result.afterCancelCode).toBe("cancelled");
  expect(result.afterReuseCode).toBe("stale_handle");
  expect(result.firstStepState).toBe("in_progress");
  expect(result.betweenCancel.status).toBe("cancelled");
  expect(result.queuedCancellationMs).toBeLessThanOrEqual(200);
  expect(result.batchDetached).toBe(true);
  expect(result.terminalCancel.status).toBe("already_terminal");
  expect(result.postBatchCancel.status).toBe("already_terminal");
  expect(result.stats.imports).toBe(0);
  expect(result.stats.datasets).toBe(0);
  expect(result.stats.cursors).toBe(0);
  expect(result.stats.transientImportInputBytesLo).toBe(0);
});

test("reports malformed inputs and rejects wrong or stale handles without leaking resources", async ({
  page,
}) => {
  await openHarness(page);
  const result = await page.evaluate(async () => {
    const codeOf = async (operation: () => Promise<unknown>): Promise<string> => {
      try {
        await operation();
        return "";
      } catch (error) {
        return (error as Error & { code?: string }).code ?? "";
      }
    };
    const failureOf = async (operation: () => Promise<unknown>): Promise<BoundaryFailure> => {
      try {
        await operation();
      } catch (error) {
        const failure = (error as { failure?: BoundaryFailure }).failure;
        if (failure !== undefined) return failure;
        throw error;
      }
      throw new Error("operation unexpectedly succeeded");
    };
    const malformedCode = await codeOf(() =>
      window.wirelensBoundary.beginImport(
        new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]),
      ),
    );
    const unsupportedCode = await codeOf(() =>
      window.wirelensBoundary.beginImport(new Uint8Array(24)),
    );
    const oversizedBlock = new Uint8Array(28);
    const oversizedView = new DataView(oversizedBlock.buffer);
    oversizedView.setUint32(0, 0x0a0d_0d0a, true);
    oversizedView.setUint32(4, 4 * 1024 * 1024 + 4, true);
    oversizedView.setUint32(8, 0x1a2b_3c4d, true);
    const oversizedFailure = await failureOf(() =>
      window.wirelensBoundary.beginImport(oversizedBlock),
    );
    const truncated = await window.wirelensBoundary.beginImport(window.wirelensFixtures.truncated());
    let truncatedCode = "";
    let truncatedStructuredWarnings: Array<{
      code: number;
      message: string;
      recovery: string;
      scope: string;
      severity: string;
    }> = [];
    let truncatedWarnings: number[] = [];
    let truncatedDataset: bigint | undefined;
    try {
      for (let index = 0; index < 20; index += 1) {
        const step = await window.wirelensBoundary.stepImport(truncated.handle, 2, 4_096);
        truncatedWarnings = Array.from(step.warningCodes ?? []);
        truncatedStructuredWarnings = step.warnings ?? [];
        if (step.state === "complete") {
          truncatedDataset = step.datasetHandle;
          break;
        }
      }
    } catch (error) {
      truncatedCode = (error as Error & { code?: string }).code ?? "";
    }
    if (truncatedDataset !== undefined) await window.wirelensBoundary.dispose(truncatedDataset);
    await window.wirelensBoundary.dispose(truncated.handle);

    const dense = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ payloadBytes: 0, records: 1_200 }),
    );
    const denseFailure = await failureOf(() =>
      window.wirelensBoundary.stepImport(dense.handle, 4_096, 16 * 1024 * 1024),
    );

    const active = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ records: 4 }),
    );
    const wrongKindCode = await codeOf(() => window.wirelensBoundary.openPacketCursor(active.handle));
    let completed: Awaited<ReturnType<typeof window.wirelensBoundary.stepImport>> | undefined;
    for (let index = 0; index < 20; index += 1) {
      completed = await window.wirelensBoundary.stepImport(active.handle, 2, 4_096);
      if (completed.state === "complete") break;
    }
    if (completed?.datasetHandle === undefined) throw new Error("fixture did not import");
    const dataset = completed.datasetHandle;
    const stepDatasetCode = await codeOf(() => window.wirelensBoundary.stepImport(dataset, 1, 1_024));
    const cursor = await window.wirelensBoundary.openPacketCursor(dataset);
    const cursorDispose = await window.wirelensBoundary.dispose(cursor);
    const repeatedCursorDispose = await window.wirelensBoundary.dispose(cursor);
    const staleCursorCode = await codeOf(() =>
      window.wirelensBoundary.readPacketBatch(cursor, 1, 1, 4_096),
    );
    const cascadingCursor = await window.wirelensBoundary.openPacketCursor(dataset);
    const datasetDispose = await window.wirelensBoundary.dispose(dataset);
    const repeatedDatasetDispose = await window.wirelensBoundary.dispose(dataset);
    const cascadedCursorCode = await codeOf(() =>
      window.wirelensBoundary.readPacketBatch(cascadingCursor, 1, 1, 4_096),
    );
    return {
      cascadedCursorCode,
      cursorDispose,
      datasetDispose,
      denseFailure,
      malformedCode,
      oversizedFailure,
      repeatedCursorDispose,
      repeatedDatasetDispose,
      staleCursorCode,
      stats: await window.wirelensBoundary.resourceStats(),
      stepDatasetCode,
      truncatedCode,
      truncatedStructuredWarnings,
      truncatedWarnings,
      unsupportedCode,
      wrongKindCode,
    };
  });

  expect(result.malformedCode).toBe("truncated_capture");
  expect(result.unsupportedCode).toBe("unsupported_format");
  expect(result.oversizedFailure).toMatchObject({
    code: "resource_limit",
    inputOffsetHi: 0,
    inputOffsetLo: 0,
    resourceLimitHi: 0,
    resourceLimitLo: 4 * 1024 * 1024,
  });
  expect(result.denseFailure).toMatchObject({
    code: "resource_limit",
    progress: {
      phase: "failed",
      totalBytesHi: 0,
      totalBytesLo: 36_024,
    },
    resourceLimitHi: 0,
    resourceLimitLo: 1_164,
  });
  expect(result.truncatedCode).toBe("");
  expect(result.truncatedWarnings).toContain(2);
  expect(result.truncatedStructuredWarnings).toEqual([
    expect.objectContaining({
      code: 2,
      message: expect.any(String),
      recovery: "record_skipped",
      scope: "capture",
      severity: "error",
      evidenceLength: 18,
      evidenceStartHi: 0,
      evidenceStartLo: 24,
    }),
  ]);
  expect(result.wrongKindCode).toBe("wrong_handle_kind");
  expect(result.stepDatasetCode).toBe("wrong_handle_kind");
  expect(result.cursorDispose.status).toBe("disposed");
  expect(result.repeatedCursorDispose.status).toBe("already_disposed");
  expect(result.staleCursorCode).toBe("stale_handle");
  expect(result.datasetDispose.status).toBe("disposed");
  expect(result.datasetDispose.dependentCursors).toBe(1);
  expect(result.repeatedDatasetDispose.status).toBe("already_disposed");
  expect(result.cascadedCursorCode).toBe("stale_handle");
  expect(result.stats.datasets).toBe(0);
  expect(result.stats.cursors).toBe(0);
  expect(result.stats.retainedCaptureBytesLo).toBe(0);
});

test("rejects non-canonical handles and bounds outstanding binary responses", async ({ page }) => {
  await openHarness(page);
  const result = await page.evaluate(async () => {
    const codeOf = async (operation: () => Promise<unknown>): Promise<string> => {
      try {
        await operation();
        return "";
      } catch (error) {
        return (error as Error & { code?: string }).code ?? "";
      }
    };
    const negativeHandleCode = await codeOf(() =>
      window.wirelensBoundary.stepImport(-1n, 1, 1_024),
    );
    const overflowingHandleCode = await codeOf(() =>
      window.wirelensBoundary.dispose(1n << 64n),
    );
    const oversizedBacking = new Uint8Array(4_096);
    const subarrayCode = await codeOf(() =>
      window.wirelensBoundary.beginImport(oversizedBacking.subarray(0, 24)),
    );
    const oversizedBackingDetached = oversizedBacking.byteLength === 0;

    const begun = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ records: 32 }),
    );
    let dataset: bigint | undefined;
    for (let index = 0; index < 100; index += 1) {
      const step = await window.wirelensBoundary.stepImport(begun.handle, 8, 4_096);
      if (step.state === "complete") {
        dataset = step.datasetHandle;
        break;
      }
    }
    if (dataset === undefined) throw new Error("binary backpressure fixture did not import");
    const cursor = await window.wirelensBoundary.openPacketCursor(dataset);
    const first = window.wirelensBoundary.readPacketBatch(cursor, 1, 4, 4_096);
    const concurrentCode = await codeOf(() =>
      window.wirelensBoundary.readEvidence(dataset as bigint, 0, 40, 14),
    );
    const batch = await first;
    const evidence = await window.wirelensBoundary.readEvidence(dataset, 0, 40, 14);

    const worker = window.wirelensBoundary.worker;
    const rawBatchRequestId = 2_000_000_101;
    const rawBatchMessages = new Promise<Array<Record<string, unknown>>>((resolve) => {
      const messages: Array<Record<string, unknown>> = [];
      const listener = (event: MessageEvent<unknown>): void => {
        if (
          typeof event.data !== "object" ||
          event.data === null ||
          (event.data as { requestId?: unknown }).requestId !== rawBatchRequestId
        ) {
          return;
        }
        messages.push(event.data as Record<string, unknown>);
        if (
          messages.some(({ kind }) => kind === "success") &&
          messages.some(({ kind }) => kind === "transfer_audit")
        ) {
          worker.removeEventListener("message", listener);
          resolve(messages);
        }
      };
      worker.addEventListener("message", listener);
    });
    worker.postMessage({
      apiVersion: 1,
      batchSchemaVersion: 1,
      cursorHandle: cursor,
      maxBytes: 4_096,
      maxRows: 4,
      operation: "read_packet_batch",
      requestId: rawBatchRequestId,
    });
    const rawBatch = await rawBatchMessages;

    const sendRaw = (
      request: Record<string, unknown> & { requestId: number },
    ): Promise<Record<string, unknown>> =>
      new Promise((resolve) => {
        const listener = (event: MessageEvent<unknown>): void => {
          if (
            typeof event.data === "object" &&
            event.data !== null &&
            (event.data as { requestId?: unknown }).requestId === request.requestId &&
            (event.data as { kind?: unknown }).kind !== "transfer_audit"
          ) {
            worker.removeEventListener("message", listener);
            resolve(event.data as Record<string, unknown>);
          }
        };
        worker.addEventListener("message", listener);
        worker.postMessage(request);
      });
    const blocked = await sendRaw({
      apiVersion: 1,
      datasetHandle: dataset,
      length: 14,
      operation: "read_evidence",
      requestId: 2_000_000_102,
      startHi: 0,
      startLo: 40,
    });
    const discarded = await sendRaw({
      apiVersion: 1,
      operation: "discard_packet_batch",
      requestId: 2_000_000_103,
      transferRequestId: rawBatchRequestId,
    });
    const acknowledged = await sendRaw({
      apiVersion: 1,
      operation: "ack_transfer",
      requestId: 2_000_000_104,
      transferRequestId: rawBatchRequestId,
    });
    const retried = await window.wirelensBoundary.readPacketBatch(cursor, 1, 4, 4_096);
    const retryStartRow = new DataView(
      retried.bytes.buffer,
      retried.bytes.byteOffset,
      retried.bytes.byteLength,
    ).getBigUint64(40, true);
    await window.wirelensBoundary.dispose(dataset);
    return {
      acknowledgedKind: acknowledged.kind,
      batchDetached: batch.workerSourceDetached,
      blockedCode: (blocked.error as { code?: unknown } | undefined)?.code,
      concurrentCode,
      discardedKind: discarded.kind,
      evidenceDetached: evidence.workerSourceDetached,
      negativeHandleCode,
      oversizedBackingDetached,
      overflowingHandleCode,
      rawBatchDetached: rawBatch.some(
        ({ detached, kind }) => kind === "transfer_audit" && detached === true,
      ),
      retryStartRow: retryStartRow.toString(),
      subarrayCode,
      stats: await window.wirelensBoundary.resourceStats(),
    };
  });

  expect(result.negativeHandleCode).toBe("invalid_handle");
  expect(result.overflowingHandleCode).toBe("invalid_handle");
  expect(result.subarrayCode).toBe("invalid_argument");
  expect(result.oversizedBackingDetached).toBe(false);
  expect(result.concurrentCode).toBe("resource_limit");
  expect(result.blockedCode).toBe("resource_limit");
  expect(result.batchDetached).toBe(true);
  expect(result.evidenceDetached).toBe(true);
  expect(result.rawBatchDetached).toBe(true);
  expect(result.discardedKind).toBe("success");
  expect(result.acknowledgedKind).toBe("success");
  expect(result.retryStartRow).toBe("4");
  expect(result.stats.datasets).toBe(0);
  expect(result.stats.cursors).toBe(0);
});

test("fail-closes packet transactions when a pending cursor becomes invalid", async ({ page }) => {
  await openHarness(page);
  const result = await page.evaluate(async () => {
    const begun = await window.wirelensBoundary.beginImport(
      window.wirelensFixtures.synthetic({ records: 8 }),
    );
    let dataset: bigint | undefined;
    for (let index = 0; index < 100; index += 1) {
      const step = await window.wirelensBoundary.stepImport(begun.handle, 4, 4_096);
      if (step.state === "complete") {
        dataset = step.datasetHandle;
        break;
      }
    }
    if (dataset === undefined) throw new Error("transaction fixture did not import");

    const worker = window.wirelensBoundary.worker;
    const sendRaw = (
      request: Record<string, unknown> & { requestId: number },
    ): Promise<Record<string, unknown>> =>
      new Promise((resolve) => {
        const listener = (event: MessageEvent<unknown>): void => {
          if (
            typeof event.data === "object" &&
            event.data !== null &&
            (event.data as { requestId?: unknown }).requestId === request.requestId &&
            (event.data as { kind?: unknown }).kind !== "transfer_audit"
          ) {
            worker.removeEventListener("message", listener);
            resolve(event.data as Record<string, unknown>);
          }
        };
        worker.addEventListener("message", listener);
        worker.postMessage(request);
      });
    const stageBatch = (
      cursorHandle: bigint,
      requestId: number,
    ): Promise<Array<Record<string, unknown>>> =>
      new Promise((resolve) => {
        const messages: Array<Record<string, unknown>> = [];
        const listener = (event: MessageEvent<unknown>): void => {
          if (
            typeof event.data !== "object" ||
            event.data === null ||
            (event.data as { requestId?: unknown }).requestId !== requestId
          ) {
            return;
          }
          messages.push(event.data as Record<string, unknown>);
          if (
            messages.some(({ kind }) => kind === "error") ||
            (messages.some(({ kind }) => kind === "success") &&
              messages.some(({ kind }) => kind === "transfer_audit"))
          ) {
            worker.removeEventListener("message", listener);
            resolve(messages);
          }
        };
        worker.addEventListener("message", listener);
        worker.postMessage({
          apiVersion: 1,
          batchSchemaVersion: 1,
          cursorHandle,
          maxBytes: 4_096,
          maxRows: 2,
          operation: "read_packet_batch",
          requestId,
        });
      });
    const invalidate = async (
      operation: "commit_packet_batch" | "discard_packet_batch",
      transferRequestId: number,
    ) => {
      const cursor = await window.wirelensBoundary.openPacketCursor(dataset as bigint);
      const staged = await stageBatch(cursor, transferRequestId);
      const disposed = await sendRaw({
        apiVersion: 1,
        handle: cursor,
        operation: "dispose",
        requestId: transferRequestId + 1,
      });
      const resolved = await sendRaw({
        apiVersion: 1,
        operation,
        requestId: transferRequestId + 2,
        transferRequestId,
      });
      const acknowledged = await sendRaw({
        apiVersion: 1,
        operation: "ack_transfer",
        requestId: transferRequestId + 3,
        transferRequestId,
      });
      return {
        acknowledged: (acknowledged.value as { acknowledged?: unknown } | undefined)?.acknowledged,
        disposalStatus: (disposed.value as { status?: unknown } | undefined)?.status,
        resolutionCode: (resolved.error as { code?: unknown } | undefined)?.code,
        resolutionKind: resolved.kind,
        sourceDetached: staged.some(
          ({ detached, kind }) => kind === "transfer_audit" && detached === true,
        ),
        stagedKinds: staged.map(({ kind }) => kind),
      };
    };

    const commit = await invalidate("commit_packet_batch", 2_000_000_201);
    const discard = await invalidate("discard_packet_batch", 2_000_000_211);
    const evidence = await window.wirelensBoundary.readEvidence(dataset, 0, 40, 1);
    await window.wirelensBoundary.dispose(dataset);
    return {
      commit,
      discard,
      evidenceDetached: evidence.workerSourceDetached,
      stats: await window.wirelensBoundary.resourceStats(),
    };
  });

  for (const transaction of [result.commit, result.discard]) {
    expect(transaction.stagedKinds).toEqual(expect.arrayContaining(["success", "transfer_audit"]));
    expect(transaction.sourceDetached).toBe(true);
    expect(transaction.disposalStatus).toBe("disposed");
    expect(transaction.resolutionKind).toBe("error");
    expect(transaction.resolutionCode).toBe("stale_handle");
    expect(transaction.acknowledged).toBe(true);
  }
  expect(result.evidenceDetached).toBe(true);
  expect(result.stats.datasets).toBe(0);
  expect(result.stats.cursors).toBe(0);
});

test("repeated sessions return logical ownership to baseline", async ({ page }) => {
  await openHarness(page);
  const result = await page.evaluate(async () => {
    const liveResources = async () => {
      const {
        peakOwnedCaptureBytesHi: _peakOwnedCaptureBytesHi,
        peakOwnedCaptureBytesLo: _peakOwnedCaptureBytesLo,
        peakTransientImportInputBytesHi: _peakTransientImportInputBytesHi,
        peakTransientImportInputBytesLo: _peakTransientImportInputBytesLo,
        ...live
      } = await window.wirelensBoundary.resourceStats();
      return live;
    };
    const baseline = await liveResources();
    for (let session = 0; session < 12; session += 1) {
      const begun = await window.wirelensBoundary.beginImport(
        window.wirelensFixtures.synthetic({ payloadBytes: 32, records: 16 }),
      );
      let dataset: bigint | undefined;
      for (let stepIndex = 0; stepIndex < 100; stepIndex += 1) {
        const step = await window.wirelensBoundary.stepImport(begun.handle, 3, 2_048);
        if (step.state === "complete") {
          dataset = step.datasetHandle;
          break;
        }
      }
      if (dataset === undefined) throw new Error("repeated fixture did not import");
      const cursor = await window.wirelensBoundary.openPacketCursor(dataset);
      await window.wirelensBoundary.readPacketBatch(cursor, 1, 4, 4_096);
      await window.wirelensBoundary.dispose(cursor);
      await window.wirelensBoundary.dispose(dataset);
      await window.wirelensBoundary.dispose(begun.handle);
    }
    const finalStats = await window.wirelensBoundary.resourceStats();
    const final = await liveResources();
    return {
      baseline,
      final,
      peakOwnedCaptureBytesLo: finalStats.peakOwnedCaptureBytesLo,
      peakTransientImportInputBytesLo: finalStats.peakTransientImportInputBytesLo,
    };
  });
  expect(result.final).toEqual(result.baseline);
  expect(result.peakOwnedCaptureBytesLo).toBeGreaterThan(0);
  expect(result.peakTransientImportInputBytesLo).toBeGreaterThan(0);
});
