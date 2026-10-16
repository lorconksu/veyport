import { defineConfig } from '@playwright/test'

// Explicit, real disposable lab. No normal E2E bootstrap, HTTP mocks, TLS
// bypass, traces, credentials or browser profiles belong in repository output.
const phases = ['MUTATIONS', 'STRESS', 'NEGATIVES', 'TIMERS', 'DIRECTORY']
if (phases.filter(phase => process.env[`VEYPORT_APPLICATION_LAB_${phase}`] === '1').length > 1) throw new Error('Run stateful disposable lab phases separately')

export default defineConfig({
  testDir: '.',
  testMatch: 'application-access.spec.ts',
  timeout: 600_000,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: 'line',
  outputDir: '../../../output/playwright/application-access',
  use: { trace: 'off', screenshot: 'off', video: 'off', ignoreHTTPSErrors: false },
})
