import { defineConfig } from "@playwright/test";

const chromiumExecutablePath = process.env.WIRELENS_CHROMIUM_EXECUTABLE;
const chromiumLaunchOptions = {
  args: ["--enable-blink-features=ForceEagerMeasureMemory"],
  ...(chromiumExecutablePath === undefined
    ? {}
    : { executablePath: chromiumExecutablePath }),
};

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
  reporter: "line",
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
        // Playwright's default headless shell omits the Performance Manager
        // instrumentation required by measureUserAgentSpecificMemory. The
        // chromium channel selects the full browser's new headless mode in CI.
        ...(chromiumExecutablePath === undefined ? { channel: "chromium" } : {}),
        launchOptions: chromiumLaunchOptions,
      },
    },
    { name: "firefox", use: { browserName: "firefox" } },
  ],
  testDir: "./tests",
  timeout: 30_000,
  use: { baseURL: "http://127.0.0.1:4174" },
  webServer: {
    command: "corepack pnpm run preview",
    port: 4174,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
