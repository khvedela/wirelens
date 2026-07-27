import { useVirtualizer } from "@tanstack/react-virtual";
import {
  type KeyboardEvent,
  type MouseEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { PacketEvidencePage } from "./packet-detail-boundary";
import type { PacketByteSelection } from "./packet-detail-model";

const BYTES_PER_ROW = 16;
const EVIDENCE_PAGE_BYTES = 4 * 1024;
const MAX_CACHED_PAGES = 16;
const HEX_ROW_HEIGHT = 32;

export interface HexGridProps {
  readonly capturedLength: number;
  readonly loadEvidencePage: (
    pageStart: number,
    signal: AbortSignal,
  ) => Promise<PacketEvidencePage>;
  readonly onByteSelection: (start: number, length: number) => void;
  readonly originalLength: number;
  readonly protocolTruncated: boolean;
  readonly selection: PacketByteSelection | null;
  readonly wireTruncated: boolean;
}

function pageStartFor(offset: number): number {
  return Math.floor(offset / EVIDENCE_PAGE_BYTES) * EVIDENCE_PAGE_BYTES;
}

function printableByte(value: number): string {
  return value >= 0x20 && value <= 0x7e ? String.fromCodePoint(value) : ".";
}

function byteLabel(offset: number, value: number): string {
  const character = printableByte(value);
  const characterText = character === "." ? "not printable" : `character ${character}`;
  return `Byte offset ${offset.toLocaleString("en-US")}, hexadecimal ${value.toString(16).padStart(2, "0").toUpperCase()}, ${characterText}`;
}

function selectionContains(selection: PacketByteSelection | null, offset: number): boolean {
  return (
    selection !== null &&
    selection.length > 0 &&
    offset >= selection.start &&
    offset < selection.start + selection.length
  );
}

function selectionFromAnchor(anchor: number, target: number): { length: number; start: number } {
  const start = Math.min(anchor, target);
  return { length: Math.max(anchor, target) - start + 1, start };
}

export function HexGrid({
  capturedLength,
  loadEvidencePage,
  onByteSelection,
  originalLength,
  protocolTruncated,
  selection,
  wireTruncated,
}: HexGridProps) {
  const scrollElement = useRef<HTMLTableElement>(null);
  const cache = useRef(new Map<number, Uint8Array>());
  const pending = useRef(new Map<number, AbortController>());
  const cacheGeneration = useRef(0);
  const focusAnchor = useRef(0);
  const pendingFocusOffset = useRef<number | null>(null);
  const [cacheVersion, setCacheVersion] = useState(0);
  const [failedPages, setFailedPages] = useState<ReadonlySet<number>>(new Set());
  const [focusedOffset, setFocusedOffset] = useState(0);
  const zeroMarkerAtCapturedEnd =
    selection?.length === 0 &&
    selection.start === capturedLength &&
    capturedLength % BYTES_PER_ROW === 0;
  const byteRowCount = Math.ceil(capturedLength / BYTES_PER_ROW);
  const rowCount = Math.max(
    byteRowCount + (zeroMarkerAtCapturedEnd ? 1 : 0),
    capturedLength === 0 ? 1 : 0,
  );
  const offsetWidth = Math.max(4, Math.max(0, capturedLength - 1).toString(16).length);

  const virtualizer = useVirtualizer({
    count: rowCount,
    estimateSize: () => HEX_ROW_HEIGHT,
    getScrollElement: () => scrollElement.current,
    overscan: 8,
    useFlushSync: false,
  });
  const virtualRows = virtualizer.getVirtualItems();
  const visibleRange = useMemo(() => {
    const first = virtualRows.at(0)?.index;
    const last = virtualRows.at(-1)?.index;
    return first === undefined || last === undefined ? null : `${first}:${last}`;
  }, [virtualRows]);

  const resetCache = useCallback(() => {
    cacheGeneration.current += 1;
    for (const controller of pending.current.values()) controller.abort();
    pending.current.clear();
    cache.current.clear();
    setFailedPages(new Set());
    setCacheVersion((version) => version + 1);
  }, []);

  useEffect(
    () => () => {
      cacheGeneration.current += 1;
      for (const controller of pending.current.values()) controller.abort();
      pending.current.clear();
    },
    [],
  );

  const requestPage = useCallback(
    (requestedStart: number) => {
      if (
        requestedStart < 0 ||
        requestedStart >= capturedLength ||
        cache.current.has(requestedStart) ||
        pending.current.has(requestedStart) ||
        failedPages.has(requestedStart)
      ) {
        return;
      }
      const generation = cacheGeneration.current;
      const controller = new AbortController();
      pending.current.set(requestedStart, controller);
      void loadEvidencePage(requestedStart, controller.signal).then(
        (page) => {
          pending.current.delete(requestedStart);
          if (controller.signal.aborted || generation !== cacheGeneration.current) return;
          const remaining = capturedLength - requestedStart;
          const expectedLength = Math.min(EVIDENCE_PAGE_BYTES, remaining);
          if (page.pageStart !== requestedStart || page.bytes.byteLength !== expectedLength) {
            setFailedPages((current) => new Set(current).add(requestedStart));
            return;
          }
          const next = cache.current;
          next.delete(requestedStart);
          next.set(requestedStart, page.bytes);
          while (next.size > MAX_CACHED_PAGES) {
            const oldest = next.keys().next().value;
            if (oldest === undefined) break;
            next.delete(oldest);
          }
          if (document.activeElement === scrollElement.current) {
            const nextFocusOffset = Math.min(requestedStart, capturedLength - 1);
            setFocusedOffset(nextFocusOffset);
            pendingFocusOffset.current = nextFocusOffset;
          }
          setCacheVersion((version) => version + 1);
        },
        () => {
          pending.current.delete(requestedStart);
          if (controller.signal.aborted || generation !== cacheGeneration.current) return;
          setFailedPages((current) => new Set(current).add(requestedStart));
        },
      );
    },
    [capturedLength, failedPages, loadEvidencePage],
  );

  useEffect(() => {
    if (visibleRange === null || capturedLength === 0) return;
    const [firstText, lastText] = visibleRange.split(":");
    const firstRow = Number.parseInt(firstText ?? "0", 10);
    const lastRow = Number.parseInt(lastText ?? "0", 10);
    const firstPage = pageStartFor(firstRow * BYTES_PER_ROW);
    const lastByte = Math.min(capturedLength - 1, (lastRow + 1) * BYTES_PER_ROW - 1);
    const lastPage = pageStartFor(lastByte);
    for (let pageStart = firstPage; pageStart <= lastPage; pageStart += EVIDENCE_PAGE_BYTES) {
      requestPage(pageStart);
    }
  }, [capturedLength, requestPage, visibleRange]);

  useEffect(() => {
    if (selection === null || selection.source !== "field" || selection.start > capturedLength) {
      return;
    }
    const targetOffset = Math.min(selection.start, Math.max(0, capturedLength - 1));
    const targetRow =
      selection.length === 0 && selection.start === capturedLength
        ? Math.floor(capturedLength / BYTES_PER_ROW)
        : Math.floor(targetOffset / BYTES_PER_ROW);
    virtualizer.scrollToIndex(targetRow, { align: "auto" });
    if (capturedLength > 0) {
      setFocusedOffset(targetOffset);
      focusAnchor.current = targetOffset;
      requestPage(pageStartFor(targetOffset));
    }
  }, [capturedLength, requestPage, selection, virtualizer]);

  const focusRenderToken = `${cacheVersion}:${visibleRange ?? "none"}`;
  useEffect(() => {
    if (focusRenderToken.length === 0) return;
    const target = pendingFocusOffset.current;
    if (target === null) return;
    const element = scrollElement.current?.querySelector<HTMLElement>(
      `[data-byte-offset="${target}"]`,
    );
    if (element === null || element === undefined) return;
    pendingFocusOffset.current = null;
    element.focus({ preventScroll: true });
  }, [focusRenderToken]);

  const byteAt = (offset: number): number | undefined => {
    const start = pageStartFor(offset);
    return cache.current.get(start)?.[offset - start];
  };

  const moveFocus = (target: number, extendSelection: boolean): void => {
    if (capturedLength === 0) return;
    const bounded = Math.max(0, Math.min(capturedLength - 1, target));
    setFocusedOffset(bounded);
    pendingFocusOffset.current = bounded;
    virtualizer.scrollToIndex(Math.floor(bounded / BYTES_PER_ROW), { align: "auto" });
    requestPage(pageStartFor(bounded));
    const targetElement = scrollElement.current?.querySelector<HTMLElement>(
      `[data-byte-offset="${bounded}"]`,
    );
    if (targetElement !== null && targetElement !== undefined) {
      pendingFocusOffset.current = null;
      targetElement.focus({ preventScroll: true });
    }
    if (extendSelection) {
      const next = selectionFromAnchor(focusAnchor.current, bounded);
      onByteSelection(next.start, next.length);
    } else {
      focusAnchor.current = bounded;
      onByteSelection(bounded, 1);
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>, offset: number): void => {
    let target: number | undefined;
    switch (event.key) {
      case "ArrowLeft":
        target = offset - 1;
        break;
      case "ArrowRight":
        target = offset + 1;
        break;
      case "ArrowUp":
        target = offset - BYTES_PER_ROW;
        break;
      case "ArrowDown":
        target = offset + BYTES_PER_ROW;
        break;
      case "Home":
        target =
          event.ctrlKey || event.metaKey ? 0 : Math.floor(offset / BYTES_PER_ROW) * BYTES_PER_ROW;
        break;
      case "End":
        target =
          event.ctrlKey || event.metaKey
            ? capturedLength - 1
            : Math.min(capturedLength - 1, Math.floor(offset / BYTES_PER_ROW) * BYTES_PER_ROW + 15);
        break;
      case "PageUp":
        target = offset - Math.max(BYTES_PER_ROW, virtualRows.length * BYTES_PER_ROW);
        break;
      case "PageDown":
        target = offset + Math.max(BYTES_PER_ROW, virtualRows.length * BYTES_PER_ROW);
        break;
      default:
        return;
    }
    event.preventDefault();
    moveFocus(target, event.shiftKey);
  };

  const handleClick = (event: MouseEvent<HTMLButtonElement>, offset: number): void => {
    setFocusedOffset(offset);
    if (event.shiftKey) {
      const next = selectionFromAnchor(focusAnchor.current, offset);
      onByteSelection(next.start, next.length);
      return;
    }
    focusAnchor.current = offset;
    onByteSelection(offset, 1);
  };

  const focusedRowIsRendered = virtualRows.some(
    ({ index }) =>
      focusedOffset >= index * BYTES_PER_ROW &&
      focusedOffset < Math.min(capturedLength, (index + 1) * BYTES_PER_ROW),
  );
  let fallbackFocusableOffset: number | undefined;
  for (const { index } of virtualRows) {
    const rowStart = index * BYTES_PER_ROW;
    const rowEnd = Math.min(capturedLength, rowStart + BYTES_PER_ROW);
    for (let offset = rowStart; offset < rowEnd; offset += 1) {
      if (byteAt(offset) !== undefined) {
        fallbackFocusableOffset = offset;
        break;
      }
    }
    if (fallbackFocusableOffset !== undefined) break;
  }
  const renderedFocusOffset =
    focusedRowIsRendered && byteAt(focusedOffset) !== undefined
      ? focusedOffset
      : fallbackFocusableOffset;

  const truncatedBytes = Math.max(0, originalLength - capturedLength);
  const truncationText = wireTruncated
    ? `${truncatedBytes.toLocaleString("en-US")} ${truncatedBytes === 1 ? "byte was" : "bytes were"} not captured on the wire.`
    : protocolTruncated
      ? "Protocol decoding stopped at a truncated field."
      : undefined;

  return (
    <>
      <table
        ref={scrollElement}
        className="hex-grid__viewport"
        data-testid="hex-grid"
        aria-label="Raw packet bytes"
        aria-rowcount={rowCount}
        aria-colcount={BYTES_PER_ROW + 2}
        aria-busy={capturedLength > 0 && cache.current.size === 0 && failedPages.size === 0}
        tabIndex={capturedLength > 0 && renderedFocusOffset === undefined ? 0 : -1}
      >
        <caption className="visually-hidden">
          Raw packet bytes. Use arrow keys to move by byte and Shift with arrow keys to extend the
          selected range.
        </caption>
        <tbody className="hex-grid" style={{ blockSize: `${virtualizer.getTotalSize()}px` }}>
          {virtualRows.map((virtualRow) => {
            const rowStart = virtualRow.index * BYTES_PER_ROW;
            const offsets = Array.from({ length: BYTES_PER_ROW }, (_, index) => rowStart + index);
            const markerOnlyRow = rowStart >= capturedLength;
            return (
              <tr
                className="hex-grid__row"
                data-index={virtualRow.index}
                key={virtualRow.key}
                aria-rowindex={virtualRow.index + 1}
                style={{
                  blockSize: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                <th className="hex-grid__address" scope="row">
                  {rowStart.toString(16).padStart(offsetWidth, "0").toUpperCase()}
                </th>
                {offsets.map((offset) => {
                  if (offset >= capturedLength) {
                    const isBoundary = selection?.length === 0 && selection.start === offset;
                    return isBoundary ? (
                      <td
                        className="hex-grid__boundary"
                        key={offset}
                        aria-label={`Insertion point at byte offset ${offset}; no captured byte`}
                      />
                    ) : (
                      <td className="hex-grid__missing" key={offset} />
                    );
                  }
                  const value = byteAt(offset);
                  if (value === undefined) {
                    return (
                      <td
                        className="hex-grid__byte hex-grid__byte--loading"
                        key={offset}
                        aria-label={`Loading byte offset ${offset}`}
                      >
                        ··
                      </td>
                    );
                  }
                  const selected = selectionContains(selection, offset);
                  const boundaryBefore = selection?.length === 0 && selection.start === offset;
                  return (
                    <td
                      className="hex-grid__cell"
                      data-boundary-before={boundaryBefore}
                      data-selected={selected}
                      key={offset}
                    >
                      <button
                        className="hex-grid__byte"
                        data-byte-offset={offset}
                        type="button"
                        aria-label={byteLabel(offset, value)}
                        aria-pressed={selected}
                        tabIndex={offset === renderedFocusOffset ? 0 : -1}
                        onClick={(event) => handleClick(event, offset)}
                        onFocus={() => setFocusedOffset(offset)}
                        onKeyDown={(event) => handleKeyDown(event, offset)}
                      >
                        {value.toString(16).padStart(2, "0").toUpperCase()}
                      </button>
                    </td>
                  );
                })}
                <td className="hex-grid__ascii" aria-hidden="true">
                  {markerOnlyRow
                    ? ""
                    : offsets.map((offset) => {
                        const value = offset < capturedLength ? byteAt(offset) : undefined;
                        const selected = selectionContains(selection, offset);
                        return (
                          <span data-selected={selected} key={offset}>
                            {value === undefined ? "·" : printableByte(value)}
                          </span>
                        );
                      })}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {failedPages.size === 0 ? null : (
        <div className="packet-detail-inline-error" role="alert">
          <span>Raw bytes could not be loaded for this range.</span>
          <button type="button" onClick={resetCache}>
            Retry
          </button>
        </div>
      )}
      {truncationText === undefined ? null : (
        <p className="hex-grid__truncation" data-testid="packet-truncation-note">
          <strong>Truncated packet</strong>
          <span>{truncationText}</span>
        </p>
      )}
    </>
  );
}
