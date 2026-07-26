import { defineConfig } from "@playwright/test";

const chromiumExecutablePath = process.env.WIRELENS_CHROMIUM_EXECUTABLE;

export default defineConfig({
  expect: { timeout: 5_000 },
  fullyParallel: false,
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
  timeout: 30_000,
  use: { baseURL: "http://127.0.0.1:4174" },
  webServer: {
    command: "corepack pnpm run preview",
    port: 4174,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
