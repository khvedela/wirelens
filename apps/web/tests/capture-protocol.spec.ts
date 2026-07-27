import { expect, test } from "@playwright/test";

import {
  CaptureImportClient,
  CaptureImportClientError,
  CapturePacketQueryCancelledError,
  CapturePacketQueryError,
  validateCaptureWorkerEvent,
} from "../src/ingestion/capture-client";
import {
  CAPTURE_INGESTION_PROTOCOL_VERSION,
  type CaptureWorkerCommand,
  type CaptureWorkerEvent,
  type ImportSummary,
} from "../src/ingestion/capture-contract";
import { reclaimImportHandle } from "../src/ingestion/import-cleanup";
import { buildPacketDetailTestBatch } from "./support/packet-detail-test-batch";

const CAPABILITIES = {
  maxCaptureBytes: 256 * 1024 * 1024,
  packetInspection: {
    detailSchemaVersion: 1,
    evidencePageBytes: 4 * 1024,
    maxCorrelationMatches: 1_024,
    maxDetailBytes: 512 * 1024,
    maxFieldsPerPacket: 1_024,
    maxLayersPerPacket: 32,
  },
  readChunkBytes: 4 * 1024 * 1024,
  wasm: {
    apiVersion: 1,
    maxImportStepBytes: 16 * 1024 * 1024,
    maxImportStepRecords: 4_096,
    maxPackets: 131_072,
  },
} as const;

const SUMMARY: ImportSummary = {
  byteLength: 24,
  byteOrder: "little-endian",
  filename: "synthetic.pcap",
  filenameHintMismatch: false,
  format: "pcap",
  packetsRetained: 0,
  records: 0,
  warningCount: 0,
};

class FakeWorker extends EventTarget {
  readonly commands: CaptureWorkerCommand[] = [];
  terminated = false;

  postMessage(message: CaptureWorkerCommand): void {
    this.commands.push(message);
  }

  terminate(): void {
    this.terminated = true;
  }

  emit(message: CaptureWorkerEvent | unknown): void {
    this.dispatchEvent(new MessageEvent("message", { data: message }));
  }

  asWorker(): Worker {
    return this as unknown as Worker;
  }
}

function initialized(requestId = 1): CaptureWorkerEvent {
  return {
    capabilities: CAPABILITIES,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId,
    type: "initialized",
  };
}

test("strictly validates every lifecycle payload before accepting it", () => {
  expect(validateCaptureWorkerEvent(initialized())).toBeDefined();
  expect(
    validateCaptureWorkerEvent({
      jobId: 2,
      lastParseProgress: {
        bytesConsumed: 40,
        diagnostics: 0,
        packetsRetained: 1,
        phase: "cancelled",
        records: 1,
        totalBytes: 100,
      },
      lastReadProgress: { bytesRead: 100, totalBytes: 100 },
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      type: "cancelled",
    }),
  ).toBeDefined();

  for (const malformed of [
    null,
    { protocolVersion: 99, requestId: 1, type: "initialized" },
    {
      capabilities: null,
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      requestId: 1,
      type: "initialized",
    },
    {
      jobId: -1,
      phase: "validating",
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      type: "progress",
    },
    {
      jobId: 2,
      phase: "reading",
      progress: { bytesRead: 11, totalBytes: 10 },
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      type: "progress",
    },
    {
      jobId: 2,
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      summary: { ...SUMMARY, records: 0, packetsRetained: 1 },
      type: "complete",
    },
    {
      jobId: 2,
      lastParseProgress: { phase: "cancelled" },
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      type: "cancelled",
    },
  ]) {
    expect(validateCaptureWorkerEvent(malformed)).toBeUndefined();
  }
});

test("a malformed worker response aborts and rejects initialization", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  const ready = client.ready();
  worker.emit({
    capabilities: null,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: 1,
    type: "initialized",
  });
  await expect(ready).rejects.toBeInstanceOf(CaptureImportClientError);
  expect(worker.terminated).toBe(true);
});

test("keeps packet inspection capability-gated for older additive v1 workers", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  const { packetInspection: _packetInspection, ...legacyCapabilities } = CAPABILITIES;
  worker.emit({
    capabilities: legacyCapabilities,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: 1,
    type: "initialized",
  });
  await expect(client.ready()).resolves.toEqual(legacyCapabilities);
  await expect(client.readPacketDetail(1, 0)).rejects.toMatchObject({
    detail: { code: "unsupported_version" },
  });
  expect(worker.commands.filter((command) => command.type === "read_packet_detail")).toEqual([]);
  client.terminate();
});

test("decodes bounded packet detail, evidence, and primary-first correlation responses", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  const detailResult = client.readPacketDetail(7, 0);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "read_packet_detail"))
    .toBeDefined();
  const detailCommand = worker.commands.find((command) => command.type === "read_packet_detail");
  if (detailCommand?.type !== "read_packet_detail") throw new Error("detail command is missing");
  expect(detailCommand).toMatchObject({
    datasetGeneration: 7,
    detailSchemaVersion: 1,
    packetId: 0,
  });
  worker.emit({
    bytes: buildPacketDetailTestBatch(),
    datasetGeneration: 7,
    packetId: 0,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: detailCommand.requestId,
    type: "packet_detail",
  });
  await expect(detailResult).resolves.toMatchObject({ packetId: 0, protocolTruncated: true });

  const evidenceResult = client.readPacketEvidencePage(7, 0, 4_096);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "read_packet_evidence_page"))
    .toBeDefined();
  const evidenceCommand = worker.commands.find(
    (command) => command.type === "read_packet_evidence_page",
  );
  if (evidenceCommand?.type !== "read_packet_evidence_page") {
    throw new Error("evidence command is missing");
  }
  const evidence = new Uint8Array([0xaa, 0xbb]);
  worker.emit({
    bytes: evidence,
    datasetGeneration: 7,
    packetId: 0,
    pageStart: 4_096,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: evidenceCommand.requestId,
    type: "packet_evidence_page",
  });
  await expect(evidenceResult).resolves.toEqual({
    bytes: evidence,
    datasetGeneration: 7,
    packetId: 0,
    pageStart: 4_096,
  });

  const selectionResult = client.resolvePacketSelection(7, 0, 4, 2);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "resolve_packet_selection"))
    .toBeDefined();
  const selectionCommand = worker.commands.find(
    (command) => command.type === "resolve_packet_selection",
  );
  if (selectionCommand?.type !== "resolve_packet_selection") {
    throw new Error("selection command is missing");
  }
  const fieldIds = new Uint32Array([15, 10]);
  worker.emit({
    datasetGeneration: 7,
    fieldIds,
    packetId: 0,
    primaryFieldId: 15,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: selectionCommand.requestId,
    selectionLength: 2,
    selectionStart: 4,
    type: "packet_selection_resolved",
  });
  await expect(selectionResult).resolves.toEqual({
    datasetGeneration: 7,
    fieldIds,
    packetId: 0,
    primaryFieldId: 15,
    selectionLength: 2,
    selectionStart: 4,
  });
  client.terminate();
});

test("packet query abort and stale errors remain isolated from the import client", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  const abortController = new AbortController();
  const cancelled = client.readPacketDetail(3, 0, abortController.signal);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "read_packet_detail"))
    .toBeDefined();
  const cancelledCommand = worker.commands.find((command) => command.type === "read_packet_detail");
  if (cancelledCommand?.type !== "read_packet_detail") throw new Error("query is missing");
  abortController.abort();
  await expect(cancelled).rejects.toBeInstanceOf(CapturePacketQueryCancelledError);
  worker.emit({
    bytes: buildPacketDetailTestBatch(),
    datasetGeneration: 3,
    packetId: 0,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: cancelledCommand.requestId,
    type: "packet_detail",
  });
  expect(worker.terminated).toBe(false);

  const stale = client.readPacketDetail(2, 0);
  await expect
    .poll(() => worker.commands.filter((command) => command.type === "read_packet_detail").length)
    .toBe(2);
  const staleCommand = worker.commands.filter(
    (command) => command.type === "read_packet_detail",
  )[1];
  if (staleCommand?.type !== "read_packet_detail") throw new Error("stale query is missing");
  worker.emit({
    datasetGeneration: 2,
    error: { code: "stale_dataset" },
    packetId: 0,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: staleCommand.requestId,
    type: "packet_query_error",
  });
  await expect(stale).rejects.toMatchObject({ detail: { code: "stale_dataset" } });
  expect(worker.terminated).toBe(false);
  client.terminate();
});

test("a late fatal packet-query failure terminates even after local cancellation", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  const abortController = new AbortController();
  const query = client.readPacketDetail(4, 0, abortController.signal);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "read_packet_detail"))
    .toBeDefined();
  const command = worker.commands.find((candidate) => candidate.type === "read_packet_detail");
  if (command?.type !== "read_packet_detail") throw new Error("detail command is missing");
  abortController.abort();
  await expect(query).rejects.toBeInstanceOf(CapturePacketQueryCancelledError);

  worker.emit({
    datasetGeneration: 4,
    error: { code: "worker_failed" },
    packetId: 0,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: command.requestId,
    type: "packet_query_error",
  });
  expect(worker.terminated).toBe(true);
  await expect(client.resourceStats()).rejects.toMatchObject({ detail: { code: "worker_failed" } });
});

test("packet selections reject the first range whose exclusive end exceeds u32", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  await expect(client.resolvePacketSelection(1, 0, 0xffff_ffff, 1)).rejects.toMatchObject({
    detail: { code: "invalid_range" },
  });
  expect(worker.commands.filter((command) => command.type === "resolve_packet_selection")).toEqual(
    [],
  );
  client.terminate();
});

test("new imports invalidate pending packet queries and malformed active results fail closed", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  const pending = client.readPacketDetail(1, 0);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "read_packet_detail"))
    .toBeDefined();
  const file = new File([new Uint8Array(24)], "synthetic.pcap");
  const imported = client.importCapture(file, () => undefined);
  await expect(pending).rejects.toMatchObject({ detail: { code: "dataset_unavailable" } });
  await expect
    .poll(() => worker.commands.find((command) => command.type === "start_import"))
    .toBeDefined();
  const start = worker.commands.find((command) => command.type === "start_import");
  if (start?.type !== "start_import") throw new Error("start command is missing");
  worker.emit({
    jobId: start.jobId,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    summary: { ...SUMMARY, datasetGeneration: 2 },
    type: "complete",
  });
  await imported;

  const malformed = client.readPacketEvidencePage(2, 0, 0);
  await expect
    .poll(() => worker.commands.find((command) => command.type === "read_packet_evidence_page"))
    .toBeDefined();
  const evidenceCommand = worker.commands.find(
    (command) => command.type === "read_packet_evidence_page",
  );
  if (evidenceCommand?.type !== "read_packet_evidence_page") {
    throw new Error("evidence command is missing");
  }
  const backing = new ArrayBuffer(4);
  worker.emit({
    bytes: new Uint8Array(backing, 1, 2),
    datasetGeneration: 2,
    packetId: 0,
    pageStart: 0,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: evidenceCommand.requestId,
    type: "packet_evidence_page",
  });
  await expect(malformed).rejects.toBeInstanceOf(CapturePacketQueryError);
  expect(worker.terminated).toBe(true);
});

test("reserves import single-flight before awaiting readiness", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  const file = new File([new Uint8Array(24)], "synthetic.pcap", {
    type: "application/vnd.tcpdump.pcap",
  });
  const first = client.importCapture(file, () => undefined);
  const second = client.importCapture(file, () => undefined);
  await expect(second).rejects.toMatchObject({ detail: { code: "invalid_selection" } });

  await expect
    .poll(() => worker.commands.find((command) => command.type === "start_import"))
    .toBeDefined();
  const start = worker.commands.find((command) => command.type === "start_import");
  if (start?.type !== "start_import") throw new Error("start command was not posted");
  worker.emit({
    jobId: start.jobId,
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    summary: SUMMARY,
    type: "complete",
  });
  await expect(first).resolves.toEqual(SUMMARY);
  client.terminate();
});

test("synchronous termination rejects pending work without waiting for a worker reply", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  const ready = client.ready();
  client.terminate();
  expect(worker.terminated).toBe(true);
  await expect(ready).rejects.toMatchObject({ detail: { code: "worker_failed" } });
});

test("graceful shutdown disposes through the worker before bounded termination", async () => {
  const worker = new FakeWorker();
  const client = new CaptureImportClient(() => worker.asWorker());
  worker.emit(initialized());
  await client.ready();

  const shutdown = client.shutdown();
  await expect
    .poll(() => worker.commands.find((command) => command.type === "shutdown"))
    .toBeDefined();
  const command = worker.commands.find((candidate) => candidate.type === "shutdown");
  if (command?.type !== "shutdown") throw new Error("shutdown command was not posted");
  expect(worker.terminated).toBe(false);
  worker.emit({
    protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
    requestId: command.requestId,
    type: "shutdown_complete",
  });
  await expect(shutdown).resolves.toBeUndefined();
  expect(worker.terminated).toBe(true);
});

test("cleanup confirms disposal even when cancellation races a terminal transition", async () => {
  const calls: string[] = [];
  const runtime = {
    async cancelImport(): Promise<never> {
      calls.push("cancel");
      throw new Error("already terminal");
    },
    async dispose() {
      calls.push("dispose");
      return { status: "disposed" as const };
    },
  };

  await expect(reclaimImportHandle(runtime, 7n, true)).resolves.toBeUndefined();
  expect(calls).toEqual(["cancel", "dispose"]);
});

test("cleanup rejects instead of forgetting a handle when disposal is unconfirmed", async () => {
  const calls: string[] = [];
  const runtime = {
    async cancelImport() {
      calls.push("cancel");
      return { status: "already_terminal" as const };
    },
    async dispose(): Promise<never> {
      calls.push("dispose");
      throw new Error("runtime invariant lost");
    },
  };

  await expect(reclaimImportHandle(runtime, 9n, true)).rejects.toThrow("runtime invariant lost");
  expect(calls).toEqual(["cancel", "dispose"]);
});
