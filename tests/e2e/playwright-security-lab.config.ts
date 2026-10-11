import { defineConfig } from '@playwright/test'

// This explicitly scoped suite uses real .59 REST, .64 transport and .60
// receipts. Sensitive login/MFA/download requests must never enter artifacts.
export default defineConfig({
  testDir: './lab',
  timeout: 900_000,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: 'line',
  outputDir: '../../output/playwright/security-lab',
  use: { baseURL: 'https://10.10.1.59:8443', trace: 'off', screenshot: 'off', video: 'off', ignoreHTTPSErrors: false },
})
