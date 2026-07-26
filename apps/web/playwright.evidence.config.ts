import { defineConfig } from "@playwright/test";

const executablePath = process.env.WIRELENS_CHROMIUM_EXECUTABLE;

export default defineConfig({
  expect: { timeout: 10_000 },
  fullyParallel: false,
  outputDir: "test-results/evidence-artifacts",
  reporter: "line",
  projects: [
    {
      name: "full-chromium-evidence",
      testMatch: "**/evidence.spec.ts",
      use: {
        browserName: "chromium",
        ...(executablePath === undefined ? { channel: "chromium" } : {}),
        launchOptions: {
          args: ["--enable-blink-features=ForceEagerMeasureMemory"],
          ...(executablePath === undefined ? {} : { executablePath }),
        },
      },
    },
  ],
  testDir: "./tests",
  timeout: 180_000,
  use: {
    baseURL: "http://127.0.0.1:4175",
    serviceWorkers: "block",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "corepack pnpm run preview",
    port: 4175,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
