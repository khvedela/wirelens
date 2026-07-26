import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";

import { expect, type Page, test } from "@playwright/test";

import type { ResourceStats } from "../src/boundary/worker-contract";
import {
  createTemporaryFixtureDirectory,
  generateBrowserIngestionFixtures,
  MIB,
} from "./support/capture-fixtures.mjs";

test.describe.configure({ mode: "serial" });

let fixtureDirectory: string;

test.beforeAll(async () => {
  fixtureDirectory = await createTemporaryFixtureDirectory("wirelens-importer-e2e-");
  await generateBrowserIngestionFixtures({
    includeArchitectureOversize: true,
    mediumPayloadBytes: 240,
    mediumRecords: 50_000,
    outputDirectory: fixtureDirectory,
    supportedLargePayloadBytes: MIB,
    supportedLargeTargetBytes: 32 * MIB,
  });
});

test.afterAll(async () => {
  await rm(fixtureDirectory, { force: true, recursive: true });
});

function fixture(name: string): string {
  return join(fixtureDirectory, name);
}

async function openIdle(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
}

async function resourceStats(page: Page): Promise<ResourceStats> {
  return page.evaluate(async () => {
    if (window.__wirelensDiagnostics === undefined) {
      throw new Error("WireLens diagnostics are unavailable");
    }
    return window.__wirelensDiagnostics.resourceStats();
  });
}

function liveResources(stats: ResourceStats) {
  const lane = (high: number, low: number): string =>
    ((BigInt(high) << 32n) | BigInt(low)).toString();
  return {
    currentOwnedCaptureBytes: lane(
      stats.currentOwnedCaptureBytesHi,
      stats.currentOwnedCaptureBytesLo,
    ),
    cursors: stats.cursors,
    datasets: stats.datasets,
    imports: stats.imports,
    retainedBatchBytes: lane(stats.retainedBatchBytesHi, stats.retainedBatchBytesLo),
    retainedCaptureBytes: lane(stats.retainedCaptureBytesHi, stats.retainedCaptureBytesLo),
    retainedIndexBytes: lane(stats.retainedIndexBytesHi, stats.retainedIndexBytesLo),
    retainedLogicalBytes: lane(stats.retainedLogicalBytesHi, stats.retainedLogicalBytesLo),
    retainedPacketIndexBytes: lane(
      stats.retainedPacketIndexBytesHi,
      stats.retainedPacketIndexBytesLo,
    ),
    totalLogicalBytesUpperBound: lane(
      stats.totalLogicalBytesUpperBoundHi,
      stats.totalLogicalBytesUpperBoundLo,
    ),
    transientAuxiliaryBytesUpperBound: lane(
      stats.transientAuxiliaryBytesUpperBoundHi,
      stats.transientAuxiliaryBytesUpperBoundLo,
    ),
    transientImportInputBytes: lane(
      stats.transientImportInputBytesHi,
      stats.transientImportInputBytesLo,
    ),
    transientPacketIndexBytesUpperBound: lane(
      stats.transientPacketIndexBytesUpperBoundHi,
      stats.transientPacketIndexBytesUpperBoundLo,
    ),
    transientParserBufferBytesUpperBound: lane(
      stats.transientParserBufferBytesUpperBoundHi,
      stats.transientParserBufferBytesUpperBoundLo,
    ),
  };
}

async function resetToIdle(page: Page): Promise<void> {
  const reset = page.getByRole("button", { name: /open another|choose another/iu });
  await reset.click();
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
}

async function dataTransfer(
  page: Page,
  files: readonly { bytes: Uint8Array; name: string; type: string }[],
) {
  return page.evaluateHandle(
    (serializedFiles) => {
      const transfer = new DataTransfer();
      for (const serialized of serializedFiles) {
        transfer.items.add(
          new File([new Uint8Array(serialized.bytes)], serialized.name, { type: serialized.type }),
        );
      }
      return transfer;
    },
    files.map(({ bytes, ...metadata }) => ({ ...metadata, bytes: Array.from(bytes) })),
  );
}

test("imports by content in the worker with no post-ready network or persistence", async ({
  page,
}) => {
  const requests: Array<{ body: string | null; url: string }> = [];
  const sockets: string[] = [];
  const errors: string[] = [];
  await openIdle(page);
  const baseline = liveResources(await resourceStats(page));
  page.on("request", (request) => requests.push({ body: request.postData(), url: request.url() }));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });

  // If product code accidentally reads on the main realm, this import fails.
  // The cloned File in the module worker has a distinct realm/prototype.
  await page.evaluate(() => {
    File.prototype.arrayBuffer = () => {
      throw new Error("main-thread File.arrayBuffer must not be called");
    };
  });
  const validBytes = await readFile(fixture("small-pcap-little-microseconds.pcap"));
  await page.locator("#capture-file-input").setInputFiles({
    buffer: validBytes,
    mimeType: "text/plain",
    name: "capture-with-a-misleading-name.txt",
  });

  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  await expect(page.getByTestId("import-summary")).toContainText("PCAP");
  await expect(page.getByText("Filename and capture contents did not match")).toBeVisible();
  const retained = await resourceStats(page);
  expect(retained.imports).toBe(0);
  expect(retained.datasets).toBe(1);
  expect(retained.cursors).toBe(0);

  const persistence = await page.evaluate(async () => ({
    cacheKeys: await caches.keys(),
    indexedDatabases: typeof indexedDB.databases === "function" ? await indexedDB.databases() : [],
    localStorageEntries: localStorage.length,
    serviceWorkerControlled: navigator.serviceWorker.controller !== null,
    serviceWorkerRegistrations: (await navigator.serviceWorker.getRegistrations()).length,
    sessionStorageEntries: sessionStorage.length,
  }));
  expect(requests).toEqual([]);
  expect(sockets).toEqual([]);
  expect(errors).toEqual([]);
  expect(persistence).toEqual({
    cacheKeys: [],
    indexedDatabases: [],
    localStorageEntries: 0,
    serviceWorkerControlled: false,
    serviceWorkerRegistrations: 0,
    sessionStorageEntries: 0,
  });

  await resetToIdle(page);
  const released = await resourceStats(page);
  expect(liveResources(released)).toEqual(baseline);
});

test("recognizes all PCAP magics and both PCAPNG byte orders", async ({ page }) => {
  await openIdle(page);
  for (const [name, expectedFormat] of [
    ["small-pcap-little-microseconds.pcap", "PCAP"],
    ["small-pcap-big-microseconds.pcap", "PCAP"],
    ["small-pcap-little-nanoseconds.pcap", "PCAP"],
    ["small-pcap-big-nanoseconds.pcap", "PCAP"],
    ["small-pcapng-little.pcapng", "PCAPNG"],
    ["small-pcapng-big.pcapng", "PCAPNG"],
  ] as const) {
    await page.locator("#capture-file-input").setInputFiles(fixture(name));
    await expect(page.getByTestId("capture-importer")).toHaveAttribute(
      "data-import-state",
      "complete",
    );
    await expect(
      page.getByTestId("import-summary").getByText(expectedFormat, { exact: true }),
    ).toBeVisible();
    await expect(page.getByTestId("import-summary")).toContainText("8");
    await resetToIdle(page);
  }

  // Native input reset allows deliberate consecutive same-file reselection.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await page
      .locator("#capture-file-input")
      .setInputFiles(fixture("small-pcap-little-microseconds.pcap"));
    await expect(page.getByTestId("capture-importer")).toHaveAttribute(
      "data-import-state",
      "complete",
    );
    if (attempt === 0) await resetToIdle(page);
  }
});

test("drag and drop uses the same importer and rejects multiple files accessibly", async ({
  page,
}) => {
  await openIdle(page);
  const bytes = new Uint8Array(await readFile(fixture("small-pcapng-little.pcapng")));
  const multiple = await dataTransfer(page, [
    { bytes, name: "one.pcapng", type: "application/x-pcapng" },
    { bytes, name: "two.pcapng", type: "application/x-pcapng" },
  ]);
  const dropzone = page.getByTestId("capture-dropzone");
  await dropzone.dispatchEvent("drop", { dataTransfer: multiple });
  await expect(page.getByRole("alert")).toContainText("Choose one capture at a time");
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
  await multiple.dispose();

  const single = await dataTransfer(page, [
    { bytes, name: "dropped.PCAPNG", type: "application/octet-stream" },
  ]);
  await dropzone.dispatchEvent("dragenter", { dataTransfer: single });
  await expect(dropzone).toHaveAttribute("data-drag-active", "true");
  await dropzone.dispatchEvent("drop", { dataTransfer: single });
  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  await expect(page.getByTestId("import-summary")).toContainText("PCAPNG");
  await single.dispose();
});

test("maps hostile files to safe errors and never retains partial datasets", async ({ page }) => {
  await openIdle(page);
  const baseline = liveResources(await resourceStats(page));
  for (const [name, expectedCode] of [
    ["empty.capture", "empty_capture"],
    ["random-magic.capture", "unsupported_format"],
    ["short-pcap-magic.pcap", "truncated_capture"],
    ["truncated-pcap-header.pcap", "truncated_capture"],
    ["malformed-pcapng-bom.pcapng", "malformed_capture"],
    ["truncated-pcapng-section.pcapng", "truncated_capture"],
    ["oversized-declared-pcap-record.pcap", "resource_limit"],
    ["oversized-declared-pcapng-block.pcapng", "resource_limit"],
    ["option-dense-pcapng.pcapng", "resource_limit"],
    ["dense-packet-admission.pcap", "resource_limit"],
  ] as const) {
    await page.locator("#capture-file-input").setInputFiles(fixture(name));
    const error = page.getByTestId("import-error");
    await expect(error).toHaveAttribute("data-error-code", expectedCode);
    await expect(error).toHaveAttribute("role", "alert");
    await expect(page.locator("#import-status-title")).toBeFocused();
    const stats = await resourceStats(page);
    expect(liveResources(stats), `${name} live resources`).toEqual(baseline);
    await resetToIdle(page);
  }

  const random = await readFile(fixture("random-magic.capture"));
  await page.locator("#capture-file-input").setInputFiles({
    buffer: random,
    mimeType: "application/vnd.tcpdump.pcap",
    name: "looks-valid.pcap",
  });
  await expect(page.getByTestId("import-error")).toHaveAttribute(
    "data-error-code",
    "unsupported_format",
  );
  await resetToIdle(page);

  await page.locator("#capture-file-input").setInputFiles(fixture("truncated-pcap-record.pcap"));
  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  await expect(
    page.getByTestId("import-summary").locator("div").filter({ hasText: "Warnings" }),
  ).toContainText("1");
  await resetToIdle(page);

  await page
    .locator("#capture-file-input")
    .setInputFiles(fixture("malformed-pcapng-footer.pcapng"));
  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  await expect(
    page.getByTestId("import-summary").locator("div").filter({ hasText: "Warnings" }),
  ).toContainText("1");
  await resetToIdle(page);
  expect(liveResources(await resourceStats(page))).toEqual(baseline);
});

test("read and parse progress stay separate and monotonic while the main thread remains responsive", async ({
  page,
}) => {
  await openIdle(page);
  await page.evaluate(() => {
    const measurements = {
      heartbeat: 0,
      longTasks: [] as number[],
      parse: [] as number[],
      read: [] as number[],
    };
    (
      window as typeof window & { __importMeasurements?: typeof measurements }
    ).__importMeasurements = measurements;
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) measurements.longTasks.push(entry.duration);
    });
    try {
      observer.observe({ entryTypes: ["longtask"] });
    } catch {
      // Firefox does not expose Long Tasks; heartbeat remains the functional gate.
    }
    const timer = window.setInterval(() => {
      measurements.heartbeat += 1;
      const read = document.querySelector<HTMLProgressElement>("#read-progress");
      const parse = document.querySelector<HTMLProgressElement>("#parse-progress");
      if (read !== null) measurements.read.push(read.value);
      if (parse !== null) measurements.parse.push(parse.value);
    }, 4);
    window.addEventListener("wirelens:stop-measurement", () => {
      window.clearInterval(timer);
      observer.disconnect();
    });
  });

  await page.locator("#capture-file-input").setInputFiles(fixture("medium.pcap"));
  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  const measurements = await page.evaluate(() => {
    window.dispatchEvent(new Event("wirelens:stop-measurement"));
    return (
      window as typeof window & {
        __importMeasurements: {
          heartbeat: number;
          longTasks: number[];
          parse: number[];
          read: number[];
        };
      }
    ).__importMeasurements;
  });
  const nondecreasing = (values: number[]) =>
    values.every((value, index) => index === 0 || value >= (values[index - 1] ?? 0));
  expect(measurements.heartbeat).toBeGreaterThan(0);
  expect(measurements.read.length).toBeGreaterThan(1);
  expect(measurements.parse.length).toBeGreaterThan(1);
  expect(nondecreasing(measurements.read)).toBe(true);
  expect(nondecreasing(measurements.parse)).toBe(true);
  expect(measurements.longTasks.filter((duration) => duration > 50)).toEqual([]);
});

test("cancels deterministically during file reading and bounded Wasm parsing", async ({ page }) => {
  await openIdle(page);
  const importer = page.getByTestId("capture-importer");
  const baseline = liveResources(await resourceStats(page));

  await page.evaluate(() => {
    const importerElement = document.querySelector('[data-testid="capture-importer"]');
    if (importerElement === null) throw new Error("importer is missing");
    const postCancelStates: string[] = [];
    (window as typeof window & { __readPostCancelStates?: string[] }).__readPostCancelStates =
      postCancelStates;
    let cancellationRequested = false;
    const cancelAtReadBoundary = new MutationObserver(() => {
      const state = importerElement.getAttribute("data-import-state");
      if (!cancellationRequested && state === "reading") {
        const button = document.querySelector<HTMLButtonElement>('[data-testid="cancel-import"]');
        if (button === null) return;
        cancellationRequested = true;
        (window as typeof window & { __readCancelRequestedAt?: number }).__readCancelRequestedAt =
          performance.now();
        button.click();
        return;
      }
      if (cancellationRequested && state !== null) {
        postCancelStates.push(state);
        if (state === "cancelled") cancelAtReadBoundary.disconnect();
      }
    });
    cancelAtReadBoundary.observe(importerElement, {
      attributeFilter: ["data-import-state"],
      attributes: true,
    });
  });
  await page.locator("#capture-file-input").setInputFiles(fixture("supported-large.pcap"));
  await expect(importer).toHaveAttribute("data-import-state", "cancelled");
  const readCancellationMs = await page.evaluate(() => {
    const requestedAt = (window as typeof window & { __readCancelRequestedAt?: number })
      .__readCancelRequestedAt;
    if (requestedAt === undefined) throw new Error("read cancellation was not requested");
    return performance.now() - requestedAt;
  });
  expect(readCancellationMs).toBeLessThan(1_000);
  const readPostCancelStates = await page.evaluate(
    () =>
      (window as typeof window & { __readPostCancelStates?: string[] }).__readPostCancelStates ??
      [],
  );
  expect(readPostCancelStates).not.toContain("validating");
  expect(readPostCancelStates).not.toContain("reading");
  expect(readPostCancelStates).not.toContain("parsing");
  expect(readPostCancelStates.at(-1)).toBe("cancelled");
  let stats = await resourceStats(page);
  expect(liveResources(stats)).toEqual(baseline);

  await resetToIdle(page);
  await page.evaluate(() => {
    const importerElement = document.querySelector('[data-testid="capture-importer"]');
    if (importerElement === null) throw new Error("importer is missing");
    const postCancelStates: string[] = [];
    (window as typeof window & { __parsePostCancelStates?: string[] }).__parsePostCancelStates =
      postCancelStates;
    let cancellationRequested = false;
    const cancelAtParseBoundary = new MutationObserver(() => {
      const state = importerElement.getAttribute("data-import-state");
      if (!cancellationRequested && state === "parsing") {
        const button = document.querySelector<HTMLButtonElement>('[data-testid="cancel-import"]');
        if (button === null) return;
        cancellationRequested = true;
        (window as typeof window & { __parseCancelRequestedAt?: number }).__parseCancelRequestedAt =
          performance.now();
        button.click();
        return;
      }
      if (cancellationRequested && state !== null) {
        postCancelStates.push(state);
        if (state === "cancelled") cancelAtParseBoundary.disconnect();
      }
    });
    cancelAtParseBoundary.observe(importerElement, {
      attributeFilter: ["data-import-state"],
      attributes: true,
    });
  });
  await page.locator("#capture-file-input").setInputFiles(fixture("medium.pcap"));
  await expect(importer).toHaveAttribute("data-import-state", "cancelled");
  const parseCancellationMs = await page.evaluate(() => {
    const requestedAt = (window as typeof window & { __parseCancelRequestedAt?: number })
      .__parseCancelRequestedAt;
    if (requestedAt === undefined) throw new Error("parse cancellation was not requested");
    return performance.now() - requestedAt;
  });
  expect(parseCancellationMs).toBeLessThan(1_000);
  const parsePostCancelStates = await page.evaluate(
    () =>
      (window as typeof window & { __parsePostCancelStates?: string[] }).__parsePostCancelStates ??
      [],
  );
  expect(parsePostCancelStates).not.toContain("validating");
  expect(parsePostCancelStates).not.toContain("reading");
  expect(parsePostCancelStates).not.toContain("parsing");
  expect(parsePostCancelStates.at(-1)).toBe("cancelled");
  stats = await resourceStats(page);
  expect(liveResources(stats)).toEqual(baseline);
});

test("rejects the >=500 MiB architecture guard before browser reading or Wasm allocation", async ({
  page,
}) => {
  await openIdle(page);
  const baseline = liveResources(await resourceStats(page));
  await page.evaluate(() => {
    const states: string[] = [];
    (window as typeof window & { __observedImportStates?: string[] }).__observedImportStates =
      states;
    const importer = document.querySelector('[data-testid="capture-importer"]');
    if (importer === null) throw new Error("importer is missing");
    new MutationObserver(() => {
      const state = importer.getAttribute("data-import-state");
      if (state !== null) states.push(state);
    }).observe(importer, { attributeFilter: ["data-import-state"], attributes: true });
  });
  await page.locator("#capture-file-input").setInputFiles(fixture("adr-0001-oversize-guard.pcap"));
  await expect(page.getByTestId("import-error")).toHaveAttribute(
    "data-error-code",
    "resource_limit",
  );
  const observedStates = await page.evaluate(
    () =>
      (window as typeof window & { __observedImportStates?: string[] }).__observedImportStates ??
      [],
  );
  expect(observedStates).not.toContain("reading");
  expect(observedStates).not.toContain("parsing");
  const stats = await resourceStats(page);
  expect(liveResources(stats)).toEqual(baseline);
});

test("restores keyboard focus after recovering from an initial worker failure", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    let workerCount = 0;
    window.Worker = class FirstInitializationFails extends NativeWorker {
      readonly shouldFailInitialization: boolean;

      constructor(scriptURL: string | URL, options?: WorkerOptions) {
        super(scriptURL, options);
        workerCount += 1;
        this.shouldFailInitialization = workerCount === 1;
      }

      override postMessage(message: unknown, transfer: Transferable[]): void;
      override postMessage(message: unknown, options?: StructuredSerializeOptions): void;
      override postMessage(
        message: unknown,
        options?: StructuredSerializeOptions | Transferable[],
      ): void {
        if (
          this.shouldFailInitialization &&
          typeof message === "object" &&
          message !== null &&
          "type" in message &&
          message.type === "initialize"
        ) {
          queueMicrotask(() => this.dispatchEvent(new ErrorEvent("error")));
          return;
        }
        if (Array.isArray(options)) super.postMessage(message, options);
        else super.postMessage(message, options);
      }
    };
  });

  await page.goto("/");
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "error");
  await expect(page.locator("#import-status-title")).toBeFocused();
  const retry = page.getByRole("button", { name: "Choose another capture" });
  await retry.focus();
  await retry.press("Enter");
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
  await expect(page.locator("#capture-file-input")).toBeFocused();
});

test("keeps the importer keyboard-accessible and reflowed at 320 CSS pixels", async ({ page }) => {
  await page.setViewportSize({ height: 800, width: 320 });
  await openIdle(page);
  await expect(
    page.getByRole("heading", { level: 1, name: "Open a packet capture" }),
  ).toBeVisible();
  await expect(page.getByTestId("privacy-notice")).toContainText("does not upload or save");
  const input = page.locator("#capture-file-input");
  await expect(input).toHaveAttribute(
    "accept",
    ".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng",
  );
  await input.focus();
  await expect(input).toBeFocused();
  const contrastRatios = await page.evaluate(() => {
    const channel = (value: number): number => {
      const normalized = value / 255;
      return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
    };
    const rgb = (value: string): [number, number, number] => {
      const components = value
        .match(/[\d.]+/gu)
        ?.slice(0, 3)
        .map(Number);
      if (components?.length !== 3) throw new Error(`unsupported color ${value}`);
      return components as [number, number, number];
    };
    const luminance = (value: string): number => {
      const [red, green, blue] = rgb(value);
      return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue);
    };
    const ratio = (foreground: string, background: string): number => {
      const lighter = Math.max(luminance(foreground), luminance(background));
      const darker = Math.min(luminance(foreground), luminance(background));
      return (lighter + 0.05) / (darker + 0.05);
    };
    const dropzone = document.querySelector<HTMLElement>(".capture-dropzone");
    const divider = document.querySelector<HTMLElement>(".dropzone-divider");
    const help = document.querySelector<HTMLElement>(".dropzone-help");
    if (dropzone === null || divider === null || help === null) {
      throw new Error("dropzone contrast targets are missing");
    }
    const background = getComputedStyle(dropzone).backgroundColor;
    return {
      divider: ratio(getComputedStyle(divider).color, background),
      help: ratio(getComputedStyle(help).color, background),
    };
  });
  expect(contrastRatios.divider).toBeGreaterThanOrEqual(4.5);
  expect(contrastRatios.help).toBeGreaterThanOrEqual(4.5);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    ),
  ).toBe(true);
  await expect(page.locator("#import-announcer")).toHaveAttribute("aria-live", "polite");
  await expect(page.getByTestId("capture-dropzone")).not.toHaveAttribute("role", "button");

  await page.emulateMedia({ forcedColors: "active" });
  expect(await page.evaluate(() => matchMedia("(forced-colors: active)").matches)).toBe(true);
  await expect(page.locator(".file-picker")).toHaveCSS("border-top-width", "2px");
  await page.emulateMedia({ forcedColors: "none", reducedMotion: "reduce" });
  expect(await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(
    true,
  );

  const chooserPromise = page.waitForEvent("filechooser");
  await input.press("Enter");
  const chooser = await chooserPromise;
  await chooser.setFiles(fixture("small-pcap-little-microseconds.pcap"));
  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  await expect(page.locator("#import-status-title")).toBeFocused();
  await page.getByTestId("open-another").click();
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
  await expect(page.locator("#capture-file-input")).toBeFocused();
});
