import { expect, test } from "@playwright/test";

import {
  CaptureImportClient,
  CaptureImportClientError,
  validateCaptureWorkerEvent,
} from "../src/ingestion/capture-client";
import {
  CAPTURE_INGESTION_PROTOCOL_VERSION,
  type CaptureWorkerCommand,
  type CaptureWorkerEvent,
  type ImportSummary,
} from "../src/ingestion/capture-contract";
import { reclaimImportHandle } from "../src/ingestion/import-cleanup";

const CAPABILITIES = {
  maxCaptureBytes: 256 * 1024 * 1024,
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
