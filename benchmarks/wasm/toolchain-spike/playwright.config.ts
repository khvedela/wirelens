import { defineConfig } from "@playwright/test";

export default defineConfig({
  expect: {
    timeout: 5_000,
  },
  fullyParallel: true,
  reporter: "line",
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "firefox", use: { browserName: "firefox" } },
  ],
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:4173",
  },
  webServer: {
    command: "corepack pnpm run preview",
    port: 4173,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
