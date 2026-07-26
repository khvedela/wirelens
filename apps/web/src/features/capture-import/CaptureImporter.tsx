import {
  type ChangeEvent,
  type DragEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  errorCopy,
  formatByteCount,
  formatCaptureFormat,
  formatCount,
  phaseDescription,
  phaseTitle,
  progressPercent,
  safeFileName,
} from "./import-copy";
import type {
  CaptureByteProgress,
  CaptureImporterProps,
  CaptureParseProgress,
} from "./import-state";

function dataTransferContainsFiles(dataTransfer: DataTransfer): boolean {
  return Array.from(dataTransfer.types).includes("Files");
}

function progressText(progress: CaptureByteProgress | undefined): string {
  if (progress === undefined || progress.totalBytes <= 0) return "Waiting";
  return `${formatByteCount(progress.bytesRead)} of ${formatByteCount(progress.totalBytes)}`;
}

interface ProgressRowProps {
  readonly id: string;
  readonly label: string;
  readonly progress?: CaptureByteProgress;
  readonly supportingText?: ReactNode;
}

function ProgressRow({ id, label, progress, supportingText }: ProgressRowProps) {
  const percentage =
    progress === undefined ? 0 : progressPercent(progress.bytesRead, progress.totalBytes);
  const valueText = progressText(progress);
  return (
    <div className="progress-row">
      <div className="progress-label">
        <label htmlFor={id}>{label}</label>
        <span aria-hidden="true">{progress === undefined ? "Waiting" : `${percentage}%`}</span>
      </div>
      <progress id={id} max={100} value={percentage} aria-valuetext={valueText} />
      <div className="progress-detail">
        <span>{valueText}</span>
        {supportingText === undefined ? null : <span>{supportingText}</span>}
      </div>
    </div>
  );
}

function parseSupportingText(progress: CaptureParseProgress | undefined): string | undefined {
  if (progress === undefined) return undefined;
  const packetLabel = progress.packetsRetained === 1 ? "packet" : "packets";
  return `${formatCount(progress.packetsRetained)} ${packetLabel}`;
}

function liveProgressMessage(
  phase: "parsing" | "reading",
  progress: CaptureByteProgress | undefined,
): string {
  if (progress === undefined || progress.totalBytes <= 0) {
    return phase === "reading" ? "Reading capture locally." : "Analyzing capture locally.";
  }
  const percentage = progressPercent(progress.bytesRead, progress.totalBytes);
  const announcedPercentage = Math.min(100, Math.floor(percentage / 10) * 10);
  return `${phase === "reading" ? "Reading capture" : "Analyzing capture"}, ${announcedPercentage} percent.`;
}

export function CaptureImporter({
  model,
  onCancel,
  onFileSelected,
  onReset,
  onSelectionRejected,
}: CaptureImporterProps) {
  const [dragActive, setDragActive] = useState(false);
  const [selectionAlert, setSelectionAlert] = useState<string>();
  const dragDepth = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);
  const restorePickerOnIdle = useRef(model.phase === "idle");
  const previousPhase = useRef(model.phase);
  const statusHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    const previous = previousPhase.current;
    previousPhase.current = model.phase;
    setSelectionAlert(undefined);
    setDragActive(false);
    dragDepth.current = 0;
    if (previous === model.phase) return undefined;

    const terminal =
      model.phase === "cancelled" || model.phase === "complete" || model.phase === "error";
    const shouldFocusPicker = model.phase === "idle" && restorePickerOnIdle.current;
    if (model.phase === "idle" || terminal) restorePickerOnIdle.current = true;
    const focusTarget = terminal
      ? statusHeading.current
      : shouldFocusPicker
        ? fileInput.current
        : null;
    if (focusTarget === null) return undefined;
    const frame = window.requestAnimationFrame(() => focusTarget.focus({ preventScroll: true }));
    return () => window.cancelAnimationFrame(frame);
  }, [model.phase]);

  const chooseFiles = (files: FileList | readonly File[]): void => {
    const selectedFiles = Array.from(files);
    const selectedFile = selectedFiles[0];
    if (selectedFiles.length !== 1 || selectedFile === undefined) {
      setSelectionAlert("Choose one capture at a time. Drop or choose one PCAP or PCAPNG capture.");
      onSelectionRejected?.({ code: "multiple_files" });
      return;
    }
    setSelectionAlert(undefined);
    onFileSelected(selectedFile);
  };

  const handleFileInput = (event: ChangeEvent<HTMLInputElement>): void => {
    const files = event.currentTarget.files;
    if (files !== null && files.length > 0) chooseFiles(files);
    // Let users deliberately choose the same file again after a terminal state.
    event.currentTarget.value = "";
  };

  const handleDragEnter = (event: DragEvent<HTMLDivElement>): void => {
    if (!dataTransferContainsFiles(event.dataTransfer)) return;
    event.preventDefault();
    dragDepth.current += 1;
    setDragActive(true);
  };

  const handleDragOver = (event: DragEvent<HTMLDivElement>): void => {
    if (!dataTransferContainsFiles(event.dataTransfer)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  };

  const handleDragLeave = (event: DragEvent<HTMLDivElement>): void => {
    if (!dataTransferContainsFiles(event.dataTransfer)) return;
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setDragActive(false);
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>): void => {
    if (!dataTransferContainsFiles(event.dataTransfer)) return;
    event.preventDefault();
    dragDepth.current = 0;
    setDragActive(false);
    chooseFiles(event.dataTransfer.files);
  };

  const liveMessage = useMemo(() => {
    if (model.phase === "error") return "";
    if (model.phase === "reading") return liveProgressMessage("reading", model.readProgress);
    if (model.phase === "parsing") {
      const progress =
        model.parseProgress === undefined
          ? undefined
          : {
              bytesRead: model.parseProgress.bytesConsumed,
              totalBytes: model.parseProgress.totalBytes,
            };
      return liveProgressMessage("parsing", progress);
    }
    return `${phaseTitle(model.phase)}. ${phaseDescription(model)}`;
  }, [model]);

  const title = phaseTitle(model.phase);
  const description = phaseDescription(model);
  const busy =
    model.phase === "booting" ||
    model.phase === "cancelling" ||
    model.phase === "parsing" ||
    model.phase === "reading" ||
    model.phase === "validating";
  const isTerminal =
    model.phase === "cancelled" || model.phase === "complete" || model.phase === "error";
  const safeName = safeFileName(model.summary?.filename ?? model.filename);
  const displayError =
    model.error?.code === "resource_limit" &&
    model.error.limitBytes === undefined &&
    model.maxCaptureBytes !== undefined
      ? { ...model.error, limitBytes: model.maxCaptureBytes }
      : model.error;
  const failure = errorCopy(displayError);

  return (
    <>
      <section
        className="importer-card"
        data-testid="capture-importer"
        data-import-state={model.phase}
        aria-labelledby="import-status-title"
        aria-busy={busy}
      >
        <div className="importer-card__heading">
          {busy ? <span className="activity-indicator" aria-hidden="true" /> : null}
          <div>
            <p className="section-kicker">Local capture import</p>
            <h2 id="import-status-title" ref={statusHeading} tabIndex={isTerminal ? -1 : undefined}>
              {title}
            </h2>
            <p>{description}</p>
          </div>
        </div>

        {model.phase === "idle" ? (
          // biome-ignore lint/a11y/noStaticElementInteractions: Drag/drop is pointer-only augmentation; the nested native file input owns keyboard activation.
          <div
            className="capture-dropzone"
            data-testid="capture-dropzone"
            data-drag-active={dragActive}
            onDragEnter={handleDragEnter}
            onDragLeave={handleDragLeave}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
          >
            <div className="capture-glyph" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
                <path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" />
              </svg>
            </div>
            <p className="dropzone-title">Drop a capture here</p>
            <p className="dropzone-divider">or</p>
            <label className="file-picker">
              <input
                id="capture-file-input"
                ref={fileInput}
                data-testid="capture-file-input"
                type="file"
                accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng"
                aria-label="Choose capture"
                aria-describedby="capture-picker-help"
                onChange={handleFileInput}
              />
              <span aria-hidden="true">Choose capture</span>
            </label>
            <p id="capture-picker-help" className="dropzone-help">
              PCAP or PCAPNG
              {model.maxCaptureBytes === undefined
                ? null
                : ` · up to ${formatByteCount(model.maxCaptureBytes)}`}
            </p>
          </div>
        ) : null}

        {model.phase === "validating" ? (
          <div className="file-context">
            <span>Selected file</span>
            <strong dir="auto">{safeName}</strong>
            {model.fileSize === undefined ? null : <span>{formatByteCount(model.fileSize)}</span>}
          </div>
        ) : null}

        {model.phase === "reading" || model.phase === "parsing" || model.phase === "cancelling" ? (
          <div className="import-progress" data-testid="import-progress">
            <div className="file-context file-context--compact">
              <span>Selected file</span>
              <strong dir="auto">{safeName}</strong>
            </div>
            <ProgressRow id="read-progress" label="Reading file" progress={model.readProgress} />
            <ProgressRow
              id="parse-progress"
              label="Analyzing capture"
              progress={
                model.parseProgress === undefined
                  ? undefined
                  : {
                      bytesRead: model.parseProgress.bytesConsumed,
                      totalBytes: model.parseProgress.totalBytes,
                    }
              }
              supportingText={parseSupportingText(model.parseProgress)}
            />
          </div>
        ) : null}

        {model.phase === "error" ? (
          <div
            className="import-alert import-alert--error"
            data-testid="import-error"
            data-error-code={model.error?.code ?? "internal_failure"}
            role="alert"
          >
            <strong>{failure.title}</strong>
            <p>{failure.body}</p>
          </div>
        ) : null}

        {model.phase === "complete" && model.summary !== undefined ? (
          <>
            <div className="import-summary" data-testid="import-summary">
              <dl>
                <div>
                  <dt>File</dt>
                  <dd dir="auto">{safeFileName(model.summary.filename)}</dd>
                </div>
                <div>
                  <dt>Format</dt>
                  <dd>{formatCaptureFormat(model.summary.format)}</dd>
                </div>
                <div>
                  <dt>Size</dt>
                  <dd>{formatByteCount(model.summary.byteLength)}</dd>
                </div>
                <div>
                  <dt>Packets</dt>
                  <dd>{formatCount(model.summary.packetsRetained)}</dd>
                </div>
                <div>
                  <dt>Warnings</dt>
                  <dd>{formatCount(model.summary.warningCount)}</dd>
                </div>
              </dl>
            </div>
            {model.summary.filenameHintMismatch ? (
              <div className="import-alert import-alert--warning">
                <strong>Filename and capture contents did not match</strong>
                <p>
                  WireLens used the detected {formatCaptureFormat(model.summary.format)} header.
                </p>
              </div>
            ) : null}
          </>
        ) : null}

        {selectionAlert === undefined ? null : (
          <div
            className="import-alert import-alert--error"
            data-testid="import-error"
            data-error-code="multiple_files"
            role="alert"
          >
            {selectionAlert}
          </div>
        )}

        <div className="import-actions">
          {model.phase === "validating" ||
          model.phase === "reading" ||
          model.phase === "parsing" ? (
            <button
              className="button button--secondary"
              data-testid="cancel-import"
              type="button"
              onClick={onCancel}
            >
              Cancel import
            </button>
          ) : null}
          {model.phase === "cancelling" ? (
            <button
              className="button button--secondary"
              data-testid="cancel-import"
              type="button"
              disabled
            >
              Cancelling…
            </button>
          ) : null}
          {model.phase === "cancelled" || model.phase === "error" ? (
            <button className="button button--primary" type="button" onClick={onReset}>
              Choose another capture
            </button>
          ) : null}
          {model.phase === "complete" ? (
            <button
              className="button button--primary"
              data-testid="open-another"
              type="button"
              onClick={onReset}
            >
              Open another capture
            </button>
          ) : null}
        </div>
      </section>
      <output
        id="import-announcer"
        className="visually-hidden"
        aria-live="polite"
        aria-atomic="true"
      >
        {liveMessage}
      </output>
    </>
  );
}
