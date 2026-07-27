import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import App from "../../App";
import type { ResourceStats } from "../../boundary/worker-contract";
import {
  CaptureImportCancelledError,
  CaptureImportClient,
  CaptureImportClientError,
  CapturePacketQueryError,
  type ImportProgressEvent,
} from "../../ingestion/capture-client";
import type { ImportSummary, IngestionCapabilities } from "../../ingestion/capture-contract";
import type { CaptureImportModel } from "./import-state";

const BOOTING_MODEL: CaptureImportModel = { phase: "booting" };

declare global {
  interface Window {
    __wirelensDiagnostics?: {
      capabilities(): Promise<IngestionCapabilities>;
      resourceStats(): Promise<ResourceStats>;
    };
  }
}

function progressModel(
  current: CaptureImportModel,
  event: ImportProgressEvent,
): CaptureImportModel {
  switch (event.phase) {
    case "validating":
      return { ...current, phase: "validating" };
    case "reading":
      return { ...current, phase: "reading", readProgress: event.progress };
    case "parsing":
      return {
        ...current,
        parseProgress: {
          bytesConsumed: event.progress.bytesConsumed,
          packetsRetained: event.progress.packetsRetained,
          records: event.progress.records,
          totalBytes: event.progress.totalBytes,
        },
        phase: "parsing",
        readProgress: {
          bytesRead: event.progress.totalBytes,
          totalBytes: event.progress.totalBytes,
        },
      };
    case "cancelling":
      return { ...current, phase: "cancelling" };
  }
}

export function CaptureImportController() {
  const [model, setModel] = useState<CaptureImportModel>(BOOTING_MODEL);
  const client = useRef<CaptureImportClient | undefined>(undefined);
  const cancellationGeneration = useRef<number | undefined>(undefined);
  const generation = useRef(0);
  const importInFlight = useRef(false);
  const liveDatasetGeneration = useRef<number | undefined>(undefined);
  const maxCaptureBytes = useRef<number | undefined>(undefined);
  const workerFailed = useRef(false);

  const initializeClient = useCallback((): CaptureImportClient => {
    const previousClient = client.current;
    if (previousClient !== undefined) previousClient.terminate();
    const currentGeneration = generation.current + 1;
    generation.current = currentGeneration;
    cancellationGeneration.current = undefined;
    importInFlight.current = false;
    liveDatasetGeneration.current = undefined;
    maxCaptureBytes.current = undefined;
    workerFailed.current = false;
    setModel(BOOTING_MODEL);
    const currentClient = new CaptureImportClient();
    client.current = currentClient;
    window.__wirelensDiagnostics = {
      capabilities: () => currentClient.ready(),
      resourceStats: () => currentClient.resourceStats(),
    };
    void currentClient.ready().then(
      (capabilities) => {
        if (generation.current !== currentGeneration) return;
        maxCaptureBytes.current = capabilities.maxCaptureBytes;
        setModel({ maxCaptureBytes: capabilities.maxCaptureBytes, phase: "idle" });
      },
      () => {
        if (generation.current !== currentGeneration) return;
        workerFailed.current = true;
        setModel({ error: { code: "worker_failed" }, phase: "error" });
      },
    );
    return currentClient;
  }, []);

  useEffect(() => {
    initializeClient();
    return () => {
      generation.current += 1;
      cancellationGeneration.current = undefined;
      importInFlight.current = false;
      liveDatasetGeneration.current = undefined;
      const ownedClient = client.current;
      client.current = undefined;
      delete window.__wirelensDiagnostics;
      if (ownedClient !== undefined) void ownedClient.shutdown().catch(() => undefined);
    };
  }, [initializeClient]);

  const handleProgress = useCallback(
    (event: ImportProgressEvent, expectedGeneration: number): void => {
      if (generation.current !== expectedGeneration) return;
      if (cancellationGeneration.current === expectedGeneration && event.phase !== "cancelling") {
        return;
      }
      setModel((current) =>
        current.phase === "cancelling" ? current : progressModel(current, event),
      );
    },
    [],
  );

  const handleComplete = useCallback((summary: ImportSummary, expectedGeneration: number): void => {
    if (generation.current !== expectedGeneration) return;
    cancellationGeneration.current = undefined;
    importInFlight.current = false;
    liveDatasetGeneration.current = summary.datasetGeneration;
    setModel({
      maxCaptureBytes: maxCaptureBytes.current,
      phase: "complete",
      summary,
    });
  }, []);

  const handleFailure = useCallback((error: unknown, expectedGeneration: number): void => {
    if (generation.current !== expectedGeneration) return;
    cancellationGeneration.current = undefined;
    importInFlight.current = false;
    liveDatasetGeneration.current = undefined;
    const terminalProgress =
      error instanceof CaptureImportCancelledError || error instanceof CaptureImportClientError
        ? error.terminalProgress
        : {};
    const preservedProgress = {
      ...(terminalProgress.lastReadProgress === undefined
        ? {}
        : { readProgress: terminalProgress.lastReadProgress }),
      ...(terminalProgress.lastParseProgress === undefined
        ? {}
        : {
            parseProgress: {
              bytesConsumed: terminalProgress.lastParseProgress.bytesConsumed,
              packetsRetained: terminalProgress.lastParseProgress.packetsRetained,
              records: terminalProgress.lastParseProgress.records,
              totalBytes: terminalProgress.lastParseProgress.totalBytes,
            },
          }),
    };
    if (error instanceof CaptureImportCancelledError) {
      setModel((current) => ({
        ...current,
        ...preservedProgress,
        maxCaptureBytes: maxCaptureBytes.current,
        phase: "cancelled",
      }));
      return;
    }
    const detail =
      error instanceof CaptureImportClientError ? error.detail : { code: "worker_failed" as const };
    workerFailed.current = detail.code === "worker_failed";
    setModel((current) => ({
      ...current,
      ...preservedProgress,
      error: detail,
      maxCaptureBytes: maxCaptureBytes.current,
      phase: "error",
    }));
  }, []);

  const onFileSelected = useCallback(
    (file: File): void => {
      const currentClient = client.current;
      if (currentClient === undefined || importInFlight.current) return;
      importInFlight.current = true;
      cancellationGeneration.current = undefined;
      liveDatasetGeneration.current = undefined;
      workerFailed.current = false;
      const expectedGeneration = generation.current + 1;
      generation.current = expectedGeneration;
      setModel({
        fileSize: file.size,
        filename: file.name,
        maxCaptureBytes: maxCaptureBytes.current,
        phase: "validating",
      });
      void currentClient
        .importCapture(file, (event) => handleProgress(event, expectedGeneration))
        .then(
          (summary) => handleComplete(summary, expectedGeneration),
          (error: unknown) => handleFailure(error, expectedGeneration),
        );
    },
    [handleComplete, handleFailure, handleProgress],
  );

  const onCancelImport = useCallback((): void => {
    if (!importInFlight.current) return;
    cancellationGeneration.current = generation.current;
    setModel((current) => ({ ...current, phase: "cancelling" }));
    client.current?.cancelImport();
  }, []);

  const onResetImport = useCallback((): void => {
    const currentClient = client.current;
    if (currentClient === undefined) return;
    if (workerFailed.current) {
      initializeClient();
      return;
    }
    const expectedGeneration = generation.current + 1;
    generation.current = expectedGeneration;
    cancellationGeneration.current = undefined;
    importInFlight.current = false;
    liveDatasetGeneration.current = undefined;
    setModel({ phase: "booting" });
    void currentClient.disposeDataset().then(
      () => {
        if (generation.current !== expectedGeneration) return;
        setModel({ maxCaptureBytes: maxCaptureBytes.current, phase: "idle" });
      },
      () => {
        if (generation.current !== expectedGeneration) return;
        workerFailed.current = true;
        setModel({ error: { code: "worker_failed" }, phase: "error" });
      },
    );
  }, [initializeClient]);

  const inspectionClient = useCallback((): {
    client: CaptureImportClient;
    datasetGeneration: number;
  } => {
    const currentClient = client.current;
    const datasetGeneration = liveDatasetGeneration.current;
    if (currentClient === undefined || datasetGeneration === undefined) {
      throw new CapturePacketQueryError({ code: "dataset_unavailable" });
    }
    return { client: currentClient, datasetGeneration };
  }, []);

  const packetInspection = useMemo(
    () => ({
      loadDetail: (packetId: number, signal: AbortSignal) => {
        const current = inspectionClient();
        return current.client.readPacketDetail(current.datasetGeneration, packetId, signal);
      },
      loadEvidence: (packetId: number, pageStart: number, signal: AbortSignal) => {
        const current = inspectionClient();
        return current.client.readPacketEvidencePage(
          current.datasetGeneration,
          packetId,
          pageStart,
          signal,
        );
      },
      resolveSelection: (packetId: number, start: number, length: number, signal: AbortSignal) => {
        const current = inspectionClient();
        return current.client.resolvePacketSelection(
          current.datasetGeneration,
          packetId,
          start,
          length,
          signal,
        );
      },
    }),
    [inspectionClient],
  );

  return (
    <App
      importModel={model}
      onCancelImport={onCancelImport}
      onFileSelected={onFileSelected}
      onResetImport={onResetImport}
      packetInspection={packetInspection}
    />
  );
}
