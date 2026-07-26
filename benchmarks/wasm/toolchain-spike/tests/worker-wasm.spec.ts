import { expect, test } from "@playwright/test";

const variants = ["direct", "wasm-pack"] as const;

function isLocalRuntimeUrl(value: string): boolean {
  const url = new URL(value);
  return (
    url.protocol === "blob:" ||
    url.protocol === "data:" ||
    (url.protocol === "http:" && url.hostname === "127.0.0.1" && url.port === "4173")
  );
}

for (const variant of variants) {
  test(`${variant} bindings load in a module worker without external requests`, async ({ page }) => {
    const externalRequests: string[] = [];
    const runtimeErrors: string[] = [];
    const wasmRequests: string[] = [];
    await page.route("**/*", async (route) => {
      const url = route.request().url();
      if (!isLocalRuntimeUrl(url)) {
        externalRequests.push(url);
        await route.abort("blockedbyclient");
        return;
      }
      await route.continue();
    });
    page.on("request", (request) => {
      const url = request.url();
      if (url.endsWith(".wasm")) {
        wasmRequests.push(url);
      }
    });
    page.on("pageerror", (error) => runtimeErrors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") {
        runtimeErrors.push(message.text());
      }
    });

    await page.goto(`/?variant=${variant}`);

    const app = page.locator("#app");
    await expect(app).toHaveAttribute("data-state", "ready");
    await expect(page.locator("#status")).toHaveText("Ready");
    await expect(page.locator("#variant")).toHaveText(variant);
    await expect(page.locator("#byte-sum")).toHaveText("265");
    await expect(page.locator("#schema-version")).toHaveText("1");
    await expect(page.locator("#worker-context")).toHaveText("DedicatedWorkerGlobalScope");
    await expect(page.locator("#transfer-state")).toHaveText("detached");

    const duration = Number(await app.getAttribute("data-duration-ms"));
    expect(Number.isFinite(duration)).toBe(true);
    expect(duration).toBeGreaterThanOrEqual(0);

    const resourceUrls = await page.evaluate(() =>
      performance.getEntriesByType("resource").map((entry) => entry.name),
    );
    expect(resourceUrls.filter((url) => !isLocalRuntimeUrl(url))).toEqual([]);
    expect(wasmRequests).toHaveLength(1);
    expect(externalRequests).toEqual([]);
    expect(runtimeErrors).toEqual([]);
  });
}
