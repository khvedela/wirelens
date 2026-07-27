import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { FieldTree } from "./FieldTree";
import { HexGrid } from "./HexGrid";
import type {
  PacketDetail,
  PacketDetailField,
  PacketEvidencePage,
  PacketFieldResolution,
} from "./packet-detail-boundary";
import {
  type FieldMatchState,
  formatByteCount,
  formatByteRange,
  type PacketByteSelection,
  rangeIsCaptured,
  selectedFieldName,
  validatedFieldMatchState,
} from "./packet-detail-model";

interface LoadingDetailState {
  readonly status: "loading";
}

interface ErrorDetailState {
  readonly status: "error";
}

interface ReadyDetailState {
  readonly detail: PacketDetail;
  readonly status: "ready";
}

type DetailState = ErrorDetailState | LoadingDetailState | ReadyDetailState;

const EMPTY_MATCH: FieldMatchState = {
  fieldIds: new Set(),
  pending: false,
  primaryFieldId: null,
};

export interface PacketDetailWorkspaceProps {
  readonly datasetGeneration: number;
  readonly loadDetail: (packetId: number, signal: AbortSignal) => Promise<PacketDetail>;
  readonly loadEvidence: (
    packetId: number,
    pageStart: number,
    signal: AbortSignal,
  ) => Promise<PacketEvidencePage>;
  readonly packetCount: number;
  readonly resolveSelection: (
    packetId: number,
    start: number,
    length: number,
    signal: AbortSignal,
  ) => Promise<PacketFieldResolution>;
}

function safePacketCount(value: number): number {
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

export function PacketDetailWorkspace({
  datasetGeneration,
  loadDetail,
  loadEvidence,
  packetCount: packetCountInput,
  resolveSelection,
}: PacketDetailWorkspaceProps) {
  const packetCount = safePacketCount(packetCountInput);
  const [packetId, setPacketId] = useState(0);
  const [packetInput, setPacketInput] = useState("1");
  const [navigationError, setNavigationError] = useState<string>();
  const [detailState, setDetailState] = useState<DetailState>({ status: "loading" });
  const [retryGeneration, setRetryGeneration] = useState(0);
  const [selection, setSelection] = useState<PacketByteSelection | null>(null);
  const [matches, setMatches] = useState<FieldMatchState>(EMPTY_MATCH);
  const [announcement, setAnnouncement] = useState("Packet detail ready.");
  const detailRequest = useRef(0);
  const detailRequestKey = useRef("");
  const previousDatasetGeneration = useRef(datasetGeneration);
  const selectionRequest = useRef(0);
  const selectionController = useRef<AbortController | undefined>(undefined);

  useEffect(() => {
    if (previousDatasetGeneration.current === datasetGeneration) return;
    previousDatasetGeneration.current = datasetGeneration;
    setPacketId(0);
    setPacketInput("1");
    setNavigationError(undefined);
  }, [datasetGeneration]);

  useEffect(() => {
    selectionController.current?.abort();
    selectionController.current = undefined;
    selectionRequest.current += 1;
    setSelection(null);
    setMatches(EMPTY_MATCH);
    if (packetCount === 0) {
      setDetailState({ status: "error" });
      return undefined;
    }
    const request = detailRequest.current + 1;
    const requestKey = `${datasetGeneration}:${packetId}:${retryGeneration}`;
    detailRequest.current = request;
    detailRequestKey.current = requestKey;
    const controller = new AbortController();
    setDetailState({ status: "loading" });
    setAnnouncement(`Loading packet ${packetId + 1}.`);
    void loadDetail(packetId, controller.signal).then(
      (detail) => {
        if (
          controller.signal.aborted ||
          detailRequest.current !== request ||
          detailRequestKey.current !== requestKey
        ) {
          return;
        }
        if (detail.packetId !== packetId) {
          setDetailState({ status: "error" });
          setAnnouncement(`Packet ${packetId + 1} could not be loaded.`);
          return;
        }
        setDetailState({ detail, status: "ready" });
        setAnnouncement(
          `Packet ${packetId + 1} ready with ${detail.fields.length.toLocaleString("en-US")} decoded fields.`,
        );
      },
      () => {
        if (
          controller.signal.aborted ||
          detailRequest.current !== request ||
          detailRequestKey.current !== requestKey
        ) {
          return;
        }
        setDetailState({ status: "error" });
        setAnnouncement(`Packet ${packetId + 1} could not be loaded.`);
      },
    );
    return () => controller.abort();
  }, [datasetGeneration, loadDetail, packetCount, packetId, retryGeneration]);

  useEffect(
    () => () => {
      detailRequest.current += 1;
      selectionRequest.current += 1;
      selectionController.current?.abort();
    },
    [],
  );

  const selectPacket = (nextPacketId: number): void => {
    if (nextPacketId < 0 || nextPacketId >= packetCount || nextPacketId === packetId) return;
    setPacketId(nextPacketId);
    setPacketInput(String(nextPacketId + 1));
    setNavigationError(undefined);
  };

  const submitPacket = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const packetNumber = Number(packetInput);
    if (!Number.isSafeInteger(packetNumber) || packetNumber < 1 || packetNumber > packetCount) {
      setNavigationError(
        `Enter a packet number from 1 through ${packetCount.toLocaleString("en-US")}.`,
      );
      return;
    }
    selectPacket(packetNumber - 1);
    setPacketInput(String(packetNumber));
    setNavigationError(undefined);
  };

  const readyDetail =
    detailState.status === "ready" && detailState.detail.packetId === packetId
      ? detailState.detail
      : undefined;

  const selectField = (field: PacketDetailField): void => {
    if (readyDetail === undefined) return;
    selectionController.current?.abort();
    selectionController.current = undefined;
    selectionRequest.current += 1;
    setMatches({ fieldIds: new Set([field.id]), pending: false, primaryFieldId: field.id });
    if (!rangeIsCaptured(field.byteRange, readyDetail.capturedLength)) {
      setSelection(null);
      setAnnouncement(`${field.name} has no valid captured byte range.`);
      return;
    }
    setSelection({ ...field.byteRange, source: "field" });
    setAnnouncement(
      field.byteRange.length === 0
        ? `${field.name} marks an insertion point at byte offset ${field.byteRange.start}; it contains no captured byte.`
        : `${field.name} selected, ${formatByteRange(field.byteRange)}.`,
    );
  };

  const selectBytes = (start: number, length: number): void => {
    if (
      readyDetail === undefined ||
      !rangeIsCaptured({ length, start }, readyDetail.capturedLength)
    ) {
      return;
    }
    const request = selectionRequest.current + 1;
    selectionRequest.current = request;
    selectionController.current?.abort();
    const controller = new AbortController();
    selectionController.current = controller;
    setSelection({ length, source: "bytes", start });
    setMatches({ fieldIds: new Set(), pending: true, primaryFieldId: null });
    setAnnouncement(`Resolving decoded fields for ${formatByteRange({ length, start })}.`);
    void resolveSelection(packetId, start, length, controller.signal).then(
      (resolution) => {
        if (controller.signal.aborted || selectionRequest.current !== request) return;
        const validatedMatches = validatedFieldMatchState(readyDetail.fields, resolution);
        if (validatedMatches === undefined) {
          setMatches(EMPTY_MATCH);
          setAnnouncement("Decoded-field correlation returned inconsistent field identities.");
          return;
        }
        const { fieldIds, primaryFieldId } = validatedMatches;
        setMatches(validatedMatches);
        const primaryName = selectedFieldName(readyDetail.fields, primaryFieldId);
        const matchText = `${fieldIds.size.toLocaleString("en-US")} matching ${fieldIds.size === 1 ? "field" : "fields"}`;
        setAnnouncement(
          `${formatByteRange({ length, start })} selected; ${matchText}.${primaryName === undefined ? "" : ` Primary field: ${primaryName}.`}`,
        );
      },
      () => {
        if (controller.signal.aborted || selectionRequest.current !== request) return;
        setMatches(EMPTY_MATCH);
        setAnnouncement("Decoded-field correlation could not be resolved for this byte range.");
      },
    );
  };

  const loadEvidencePage = useCallback(
    (pageStart: number, signal: AbortSignal) => loadEvidence(packetId, pageStart, signal),
    [loadEvidence, packetId],
  );

  if (packetCount === 0) {
    return (
      <section
        className="packet-detail-workspace packet-detail-workspace--empty"
        aria-labelledby="packet-detail-title"
      >
        <div>
          <p className="section-kicker">Packet evidence</p>
          <h2 id="packet-detail-title">No retained packets</h2>
          <p className="packet-detail-workspace__description">
            This capture has no packet evidence to inspect.
          </p>
        </div>
      </section>
    );
  }

  const selectedPrimaryName =
    readyDetail === undefined
      ? undefined
      : selectedFieldName(readyDetail.fields, matches.primaryFieldId);

  return (
    <section
      className="packet-detail-workspace"
      data-testid="packet-detail-workspace"
      data-packet-id={packetId}
      aria-labelledby="packet-detail-title"
      aria-busy={detailState.status === "loading"}
    >
      <header className="packet-detail-workspace__header">
        <div>
          <p className="section-kicker">Packet evidence</p>
          <h2 id="packet-detail-title">Inspect decoded fields and raw bytes</h2>
          <p className="packet-detail-workspace__description">
            Packet {packetId + 1} of {packetCount.toLocaleString("en-US")}
            {readyDetail === undefined
              ? ""
              : ` · ${formatByteCount(readyDetail.capturedLength)} captured`}
          </p>
        </div>
        <div className="packet-detail-workspace__actions">
          <form
            className="packet-navigation"
            aria-label="Packet navigation"
            onSubmit={submitPacket}
          >
            <button
              className="button button--secondary packet-navigation__step"
              disabled={packetId === 0}
              type="button"
              aria-label="Previous packet"
              onClick={() => selectPacket(packetId - 1)}
            >
              ‹
            </button>
            <label htmlFor="packet-number">Packet</label>
            <input
              id="packet-number"
              inputMode="numeric"
              max={packetCount}
              min={1}
              type="number"
              value={packetInput}
              aria-invalid={navigationError !== undefined}
              aria-describedby={
                navigationError === undefined ? undefined : "packet-navigation-error"
              }
              onChange={(event) => setPacketInput(event.currentTarget.value)}
            />
            <span aria-hidden="true">/ {packetCount.toLocaleString("en-US")}</span>
            <button className="button button--secondary" type="submit">
              Go
            </button>
            <button
              className="button button--secondary packet-navigation__step"
              disabled={packetId >= packetCount - 1}
              type="button"
              aria-label="Next packet"
              onClick={() => selectPacket(packetId + 1)}
            >
              ›
            </button>
          </form>
        </div>
        {navigationError === undefined ? null : (
          <p id="packet-navigation-error" className="packet-navigation__error" role="alert">
            {navigationError}
          </p>
        )}
      </header>

      {detailState.status === "loading" ? (
        <div className="packet-detail-status" data-testid="packet-detail-loading" role="status">
          <span className="activity-indicator" aria-hidden="true" />
          <span>Loading packet detail…</span>
        </div>
      ) : null}
      {detailState.status === "error" ? (
        <div className="packet-detail-status packet-detail-status--error" role="alert">
          <div>
            <strong>Packet detail is unavailable</strong>
            <p>The bounded packet evidence could not be loaded. You can try this packet again.</p>
          </div>
          <button
            className="button button--secondary"
            type="button"
            onClick={() => setRetryGeneration((generation) => generation + 1)}
          >
            Retry
          </button>
        </div>
      ) : null}
      {readyDetail === undefined ? null : (
        <div className="packet-detail-workspace__panes">
          <section className="packet-detail-panel" aria-labelledby="decoded-fields-title">
            <header className="packet-detail-panel__header">
              <div>
                <h3 id="decoded-fields-title">Decoded fields</h3>
                <p>{readyDetail.fields.length.toLocaleString("en-US")} fields</p>
              </div>
              {matches.pending ? <span className="packet-detail-chip">Matching…</span> : null}
              {!matches.pending && matches.fieldIds.size > 0 ? (
                <span className="packet-detail-chip">
                  {matches.fieldIds.size.toLocaleString("en-US")} matched
                </span>
              ) : null}
            </header>
            <FieldTree
              key={`${datasetGeneration}:${readyDetail.packetId}`}
              detail={readyDetail}
              matchedFieldIds={matches.fieldIds}
              onFieldSelected={selectField}
              primaryFieldId={matches.primaryFieldId}
            />
          </section>
          <section className="packet-detail-panel" aria-labelledby="raw-bytes-title">
            <header className="packet-detail-panel__header">
              <div>
                <h3 id="raw-bytes-title">Raw bytes</h3>
                <p>
                  {selection === null
                    ? "Select a field or byte"
                    : selection.length === 0
                      ? `Insertion point at ${selection.start.toLocaleString("en-US")}`
                      : formatByteRange(selection)}
                </p>
              </div>
              {selectedPrimaryName === undefined ? null : (
                <span className="packet-detail-chip packet-detail-chip--primary">
                  {selectedPrimaryName}
                </span>
              )}
            </header>
            <HexGrid
              key={`${datasetGeneration}:${readyDetail.packetId}`}
              capturedLength={readyDetail.capturedLength}
              loadEvidencePage={loadEvidencePage}
              onByteSelection={selectBytes}
              originalLength={readyDetail.originalLength}
              protocolTruncated={readyDetail.protocolTruncated}
              selection={selection}
              wireTruncated={readyDetail.wireTruncated}
            />
          </section>
        </div>
      )}
      <output className="visually-hidden" aria-live="polite" aria-atomic="true">
        {announcement}
      </output>
    </section>
  );
}
