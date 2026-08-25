import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/browser",
  timeout: 30000,
  use: { baseURL: "http://127.0.0.1:18787", headless: true },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "firefox", use: { browserName: "firefox" } },
    { name: "webkit", use: { browserName: "webkit" } },
  ],
  webServer: {
    command: ".venv/bin/technocore-worker web --host 127.0.0.1 --port 18787",
    url: "http://127.0.0.1:18787",
    reuseExistingServer: false,
  },
});
