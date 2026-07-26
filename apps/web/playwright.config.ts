import { defineConfig } from "@playwright/test";

const chromiumExecutablePath = process.env.WIRELENS_CHROMIUM_EXECUTABLE;

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  outputDir: "test-results/artifacts",
  reporter: "line",
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
        ...(chromiumExecutablePath === undefined
          ? {}
          : { launchOptions: { executablePath: chromiumExecutablePath } }),
      },
    },
    { name: "firefox", use: { browserName: "firefox" } },
  ],
  testDir: "./tests",
  testIgnore: "**/evidence.spec.ts",
  timeout: 45_000,
  use: {
    baseURL: "http://127.0.0.1:4175",
    serviceWorkers: "allow",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "corepack pnpm run preview",
    port: 4175,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
