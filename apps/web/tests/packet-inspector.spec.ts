import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, type Page, test } from "@playwright/test";

import {
  createPacketInspectorFixtureBytes,
  createTemporaryFixtureDirectory,
} from "./support/capture-fixtures.mjs";

test.describe.configure({ mode: "serial" });

let fixtureDirectory: string;
let fixturePath: string;

test.beforeAll(async () => {
  fixtureDirectory = await createTemporaryFixtureDirectory("wirelens-packet-inspector-");
  fixturePath = join(fixtureDirectory, "packet-inspector.pcap");
  await writeFile(fixturePath, createPacketInspectorFixtureBytes(), {
    flag: "wx",
    mode: 0o600,
  });
});

test.afterAll(async () => {
  await rm(fixtureDirectory, { force: true, recursive: true });
});

async function openInspector(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByTestId("capture-importer")).toHaveAttribute("data-import-state", "idle");
  await page.locator("#capture-file-input").setInputFiles(fixturePath);
  await expect(page.getByTestId("capture-importer")).toHaveAttribute(
    "data-import-state",
    "complete",
  );
  await expect(page.getByTestId("packet-detail-workspace")).toHaveAttribute("data-packet-id", "0");
  await expect(page.getByTestId("packet-detail-loading")).toHaveCount(0);
  await expect(page.getByText("ethernet", { exact: true })).toBeVisible();
}

function byte(page: Page, offset: number) {
  return page.locator(`[data-byte-offset="${offset}"]`);
}

function fieldRow(page: Page, name: string) {
  return page.locator(".field-tree__row", {
    has: page.locator(".field-tree__name", { hasText: new RegExp(`^${name}$`, "u") }),
  });
}

test("correlates decoded fields and raw bytes in both directions with keyboard ranges", async ({
  page,
}) => {
  await openInspector(page);

  const ethernet = fieldRow(page, "ethernet");
  const ethernetDestination = fieldRow(page, "destination");
  await ethernet.focus();
  await ethernet.press("ArrowDown");
  await expect(ethernetDestination).toBeFocused();
  await ethernetDestination.press("Enter");
  for (let offset = 0; offset < 6; offset += 1) {
    await expect(byte(page, offset)).toHaveAttribute("aria-pressed", "true");
  }
  await expect(byte(page, 6)).toHaveAttribute("aria-pressed", "false");

  await byte(page, 36).click();
  const destinationPort = fieldRow(page, "destination_port");
  await expect(destinationPort).toHaveAttribute("data-primary", "true");
  await expect(destinationPort).toHaveAttribute("data-matched", "true");
  expect(await page.locator('.field-tree__row[data-matched="true"]').count()).toBeGreaterThan(1);

  await byte(page, 36).press("Shift+ArrowRight");
  await expect(byte(page, 36)).toHaveAttribute("aria-pressed", "true");
  await expect(byte(page, 37)).toHaveAttribute("aria-pressed", "true");
  await expect(destinationPort).toHaveAttribute("data-primary", "true");
  await expect(page.locator(".packet-detail-panel").filter({ hasText: "Raw bytes" })).toContainText(
    "36–37 · 2 bytes",
  );

  const fieldViewport = page.getByTestId("field-tree-viewport");
  await fieldViewport.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    element.dispatchEvent(new Event("scroll"));
  });
  await expect(fieldViewport.locator('.field-tree__row[tabindex="0"]')).toHaveCount(1);
});

test("handles a zero-byte truncated packet and rapid navigation", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  await openInspector(page);

  await page.getByRole("button", { name: "Next packet" }).click();
  await expect(page.getByTestId("packet-detail-workspace")).toHaveAttribute("data-packet-id", "1");
  await expect(page.getByText("ethernet", { exact: true })).toBeVisible();
  await fieldRow(page, "ethernet").click();
  await expect(page.getByLabel("Insertion point at byte offset 0; no captured byte")).toBeVisible();
  await expect(page.getByTestId("packet-truncation-note")).toContainText(
    "14 bytes were not captured on the wire",
  );
  await expect(page.locator(".hex-grid__byte")).toHaveCount(0);

  await page.getByRole("button", { name: "Next packet" }).click();
  await page.getByRole("button", { name: "Previous packet" }).click();
  await page.getByRole("button", { name: "Previous packet" }).click();
  await expect(page.getByTestId("packet-detail-workspace")).toHaveAttribute("data-packet-id", "0");
  await expect(page.getByText("destination", { exact: true })).toBeVisible();
  await expect(page.getByText("Packet 1 of 3", { exact: false })).toBeVisible();
  expect(runtimeErrors).toEqual([]);
});

test("pages and virtualizes wide evidence without external traffic or browser storage", async ({
  page,
}) => {
  await page.setViewportSize({ height: 800, width: 320 });
  const externalRequests: string[] = [];
  const sockets: string[] = [];
  const runtimeErrors: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== "http://127.0.0.1:4175") externalRequests.push(request.url());
  });
  page.on("websocket", (socket) => sockets.push(socket.url()));
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  await openInspector(page);

  await page.getByRole("button", { name: "Next packet" }).click();
  await page.getByRole("button", { name: "Next packet" }).click();
  await expect(page.getByTestId("packet-detail-workspace")).toHaveAttribute("data-packet-id", "2");

  const grid = page.getByTestId("hex-grid");
  await expect
    .poll(() => grid.evaluate((element) => element.scrollHeight - element.clientHeight))
    .toBeGreaterThan(8_192);
  await grid.evaluate((element) => {
    element.scrollTop = 8192;
    element.dispatchEvent(new Event("scroll"));
  });
  await expect
    .poll(() => grid.evaluate((element) => element.scrollTop))
    .toBeGreaterThanOrEqual(8_192);
  await expect.poll(() => byte(page, 4_096).count()).toBe(1);
  await expect(byte(page, 4_096)).toHaveText("42");
  const gridTabStop = grid.locator('[data-byte-offset][tabindex="0"]');
  await expect(gridTabStop).toHaveCount(1);
  await gridTabStop.focus();
  await expect(gridTabStop).toBeFocused();
  await byte(page, 4_096).click();
  await expect(byte(page, 4_096)).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator('.field-tree__row[data-matched="true"]')).toHaveCount(0);

  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    ),
  ).toBe(true);
  await page.emulateMedia({ forcedColors: "active" });
  await expect(byte(page, 4_096).locator("..")).toHaveCSS("border-top-width", "2px");

  const storage = await page.evaluate(async () => ({
    cacheKeys: await caches.keys(),
    local: localStorage.length,
    session: sessionStorage.length,
  }));
  expect(storage).toEqual({ cacheKeys: [], local: 0, session: 0 });
  expect(externalRequests).toEqual([]);
  expect(sockets).toEqual([]);
  expect(runtimeErrors).toEqual([]);
});
