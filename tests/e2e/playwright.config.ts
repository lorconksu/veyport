import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  testIgnore: 'screenshots.spec.ts',
  timeout: 60000,
  retries: 1,
  fullyParallel: false,
  // The suite shares a single TOTP-backed test account. Serializing CI workers
  // avoids cross-worker code reuse and intermittent auth failures.
  workers: process.env.CI ? 1 : undefined,
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:18081',
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
  },
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
})
