/**
 * Screenshot capture spec — standalone, does NOT use global setup/teardown.
 *
 * Spins up its own fresh Docker container so we can capture the setup flow
 * (before any account exists) as well as all authenticated pages.
 *
 * Run standalone:
 *   cd tests/e2e && npx playwright test screenshots.spec.ts --config playwright-screenshots.config.ts
 */

import { test, expect, type Page } from '@playwright/test'
import { authenticator } from 'otplib'
import { spawnSync } from 'child_process'
import fs from 'fs'
import path from 'path'

// Container / network config for the screenshot run
const CONTAINER_NAME = 'veyport-screenshots'
const AGENT_CONTAINER_NAME = 'veyport-screenshots-agent'
const NETWORK_NAME = 'veyport-screenshots-net'
const HTTP_PORT = '18082'
const BASE_URL = `http://localhost:${HTTP_PORT}`
const IMAGE = process.env.E2E_IMAGE || 'veyport:latest'

// Output directory — project root docs/screenshots/
const SCREENSHOT_DIR = path.resolve(__dirname, '../../../docs/screenshots')
const WIKI_SCREENSHOT_DIR = path.resolve(__dirname, '../../../docs/wiki/screenshots')

// Credentials
const USERNAME = 'admin'
const PASSWORD = 'E2eTestPass!2026'
const EMAIL = 'admin@example.com'

// Shared state across tests (serial execution)
let totpSecret = ''
let lastUsedTOTPCode = ''

// Auth tokens
let authTokens: { access_token: string; refresh_token: string } | null = null
let docsServer: { id: string; name: string } | null = null

/**
 * Wait until the TOTP code changes from the last used one.
 * Prevents code-reuse rejections when multiple tests use TOTP in the same 30s window.
 */
async function waitForFreshTOTPCode(): Promise<string> {
  if (!lastUsedTOTPCode) return authenticator.generate(totpSecret)
  for (let i = 0; i < 35; i++) {
    const code = authenticator.generate(totpSecret)
    if (code !== lastUsedTOTPCode) return code
    await new Promise(r => setTimeout(r, 1000))
  }
  throw new Error('TOTP code did not rotate within 35s')
}

// ---------------------------------------------------------------------------
// Container lifecycle helpers
// ---------------------------------------------------------------------------
function runDocker(args: string[], errorPrefix: string) {
  const result = spawnSync('docker', args, { stdio: 'pipe' })
  if (result.status !== 0) {
    throw new Error(`${errorPrefix}: ${result.stderr?.toString()}`)
  }
  return result.stdout?.toString() ?? ''
}

function startContainer() {
  spawnSync('docker', ['rm', '-f', AGENT_CONTAINER_NAME], { stdio: 'pipe' })
  spawnSync('docker', ['rm', '-f', CONTAINER_NAME], { stdio: 'pipe' })
  spawnSync('docker', ['network', 'rm', NETWORK_NAME], { stdio: 'pipe' })
  runDocker(['network', 'create', NETWORK_NAME], 'Failed to create screenshot network')

  runDocker([
    'run', '-d',
    '--name', CONTAINER_NAME,
    '--network', NETWORK_NAME,
    '-p', `${HTTP_PORT}:8081`,
    IMAGE,
    '--addr', ':8081',
    '--grpc-addr', ':9090',
    '--db', '/data/veyport.db',
    '--agent-bin-dir', '/app',
    '--grpc-external-addr', `${CONTAINER_NAME}:9090`,
  ], 'Failed to start container')
}

async function waitForReady(timeoutSec = 30) {
  for (let i = 0; i < timeoutSec; i++) {
    try {
      const res = await fetch(`${BASE_URL}/api/auth/status`)
      if (res.ok) {
        console.log(`Screenshot container ready after ${i + 1}s`)
        return
      }
    } catch { /* not ready */ }
    await new Promise(r => setTimeout(r, 1000))
  }
  throw new Error(`Container not ready after ${timeoutSec}s`)
}

function stopContainer() {
  spawnSync('docker', ['rm', '-f', AGENT_CONTAINER_NAME], { stdio: 'pipe' })
  spawnSync('docker', ['rm', '-f', CONTAINER_NAME], { stdio: 'pipe' })
  spawnSync('docker', ['network', 'rm', NETWORK_NAME], { stdio: 'pipe' })
}

// ---------------------------------------------------------------------------
// Auth helper — obtains fresh tokens via Node.js fetch, injects into page
// ---------------------------------------------------------------------------
async function obtainFreshTokens(): Promise<{ access_token: string; refresh_token: string }> {
  const code = await waitForFreshTOTPCode()

  const loginResp = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
  })
  if (!loginResp.ok) {
    throw new Error(`Login API failed: ${loginResp.status} ${await loginResp.text()}`)
  }
  const loginData = (await loginResp.json()) as { totp_token: string }

  const totpResp = await fetch(`${BASE_URL}/api/auth/login/totp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ totp_token: loginData.totp_token, code }),
  })
  if (!totpResp.ok) {
    throw new Error(`TOTP API failed: ${totpResp.status} ${await totpResp.text()}`)
  }

  lastUsedTOTPCode = code
  const tokens = (await totpResp.json()) as { access_token: string; refresh_token: string }
  authTokens = tokens
  return tokens
}

async function injectAuth(page: Page, targetPath = '/') {
  // Obtain fresh tokens if we don't have any yet
  if (!authTokens) {
    await obtainFreshTokens()
  }

  const expires = Math.floor(Date.now() / 1000)
  await page.context().addCookies([
    {
      name: 'veyport_access',
      value: authTokens!.access_token,
      domain: 'localhost',
      path: '/',
      expires: expires + 900,
      httpOnly: true,
      secure: false,
      sameSite: 'Strict',
    },
    {
      name: 'veyport_refresh',
      value: authTokens!.refresh_token,
      domain: 'localhost',
      path: '/api/auth/refresh',
      expires: expires + 604800,
      httpOnly: true,
      secure: false,
      sameSite: 'Strict',
    },
    {
      name: 'veyport_csrf',
      value: 'screenshots-csrf',
      domain: 'localhost',
      path: '/',
      expires: expires + 604800,
      httpOnly: false,
      secure: false,
      sameSite: 'Strict',
    },
  ])

  await page.goto(BASE_URL + targetPath)
  await page.waitForLoadState('domcontentloaded')
}

async function ensureDocsServerOnline(): Promise<{ id: string; name: string }> {
  if (docsServer) {
    return docsServer
  }
  if (!authTokens) {
    await obtainFreshTokens()
  }

  const serverResp = await fetch(`${BASE_URL}/api/servers`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${authTokens!.access_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: 'docs-node-1',
      labels: JSON.stringify({ env: 'docs', role: 'gateway' }),
    }),
  })
  if (!serverResp.ok) {
    throw new Error(`Create docs server failed: ${serverResp.status} ${await serverResp.text()}`)
  }
  const created = (await serverResp.json()) as {
    server: { id: string; name: string }
    registration_token: string
    install_command: string
  }
  const caPin = /--ca-pin '([^']+)'/.exec(created.install_command)?.[1]
  if (!caPin) {
    throw new Error('Create docs server response did not include a CA pin in install_command')
  }

  spawnSync('docker', ['rm', '-f', AGENT_CONTAINER_NAME], { stdio: 'pipe' })
  runDocker([
    'run', '-d',
    '--name', AGENT_CONTAINER_NAME,
    '--network', NETWORK_NAME,
    '--entrypoint', '/app/veyport-agent-linux-amd64',
    IMAGE,
    '--hub', `${CONTAINER_NAME}:9090`,
    '--token', created.registration_token,
    '--ca-pin', caPin,
    '--config', '/tmp/veyport-agent.conf',
    '--cert-dir', '/tmp/veyport-tls',
    '--dropzone-dir', '/tmp/veyport-dropzone',
    '--allowed-paths', '/,/app,/tmp',
  ], 'Failed to start screenshot agent')

  for (let i = 0; i < 45; i++) {
    const res = await fetch(`${BASE_URL}/api/servers/${created.server.id}`, {
      headers: { Authorization: `Bearer ${authTokens!.access_token}` },
    })
    if (res.ok) {
      const serverData = (await res.json()) as { status: string }
      if (serverData.status === 'online') {
        docsServer = created.server
        return docsServer
      }
    }
    await new Promise(r => setTimeout(r, 1000))
  }

  throw new Error('Screenshot agent did not come online within 45s')
}

// ---------------------------------------------------------------------------
// Screenshot helper
// ---------------------------------------------------------------------------
function screenshotPath(name: string) {
  return path.join(SCREENSHOT_DIR, name)
}

const wikiScreenshotMap: Record<string, string[]> = {
  '03-login-page.png': ['login.png'],
  '04-totp-login.png': ['totp.png'],
  '05-fleet-dashboard.png': ['dashboard.png'],
  '07-audit-logs.png': ['audit-logs.png'],
  '08-settings-profile.png': ['settings-profile.png'],
  '09-settings-users.png': ['settings-users.png'],
  '10-server-detail-filetree.png': ['server-detail.png', 'file-browser.png'],
  '12-settings-notifications.png': ['settings-notifications.png'],
  '13-server-detail-terminal.png': ['terminal.png'],
}

async function captureDocScreenshot(page: Page, name: string) {
  await page.screenshot({
    path: screenshotPath(name),
    fullPage: true,
  })
  const wikiNames = wikiScreenshotMap[name] ?? []
  for (const wikiName of wikiNames) {
    await page.screenshot({
      path: path.join(WIKI_SCREENSHOT_DIR, wikiName),
      fullPage: true,
    })
  }
}

// ---------------------------------------------------------------------------
// Tests — serial execution
// ---------------------------------------------------------------------------
test.describe.configure({ mode: 'serial' })

test.describe('Screenshot capture', () => {
  test.beforeAll(async () => {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true })
    fs.mkdirSync(WIKI_SCREENSHOT_DIR, { recursive: true })
    startContainer()
    await waitForReady()
  })

  test.afterAll(async () => {
    stopContainer()
  })

  // 01 — Setup page (fresh system, no account)
  test('01-setup-page', async ({ page }) => {
    await page.goto(`${BASE_URL}/`)
    await expect(page).toHaveURL(/\/setup$/, { timeout: 10000 })
    await expect(page.getByRole('button', { name: 'Create Account' })).toBeVisible()

    await captureDocScreenshot(page, '01-setup-page.png')
  })

  // 02 — TOTP setup screen (after account creation)
  test('02-totp-setup', async ({ page }) => {
    await page.goto(`${BASE_URL}/setup`)
    await expect(page.getByRole('button', { name: 'Create Account' })).toBeVisible()

    await page.getByPlaceholder('username').fill(USERNAME)
    await page.getByPlaceholder('email').fill(EMAIL)
    await page.getByPlaceholder('password (min 12 chars)').fill(PASSWORD)
    await page.getByRole('button', { name: 'Create Account' }).click()

    await expect(page).toHaveURL(/\/setup\/totp$/, { timeout: 10000 })

    const secretEl = page.locator('code')
    await expect(secretEl).toBeVisible({ timeout: 10000 })
    totpSecret = (await secretEl.textContent()) ?? ''
    expect(totpSecret.length).toBeGreaterThan(10)

    await captureDocScreenshot(page, '02-totp-setup.png')

    // Complete TOTP setup
    const code = authenticator.generate(totpSecret)
    const inputs = page.locator('input[inputmode="numeric"]')
    await expect(inputs).toHaveCount(6)
    for (let i = 0; i < 6; i++) {
      await inputs.nth(i).fill(code[i])
    }
    lastUsedTOTPCode = code
    await expect(page).toHaveURL(new RegExp(`^${BASE_URL}/?$`), { timeout: 15000 })
  })

  // 03 — Login page
  test('03-login-page', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`)
    await expect(page).toHaveURL(/\/login$/, { timeout: 10000 })
    await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible()

    await captureDocScreenshot(page, '03-login-page.png')
  })

  // 04 — TOTP login verification page + obtain auth tokens for later tests
  test('04-totp-login', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`)
    await page.getByPlaceholder('username').fill(USERNAME)
    await page.getByPlaceholder('password').fill(PASSWORD)
    await page.getByRole('button', { name: 'Sign In' }).click()

    await expect(page).toHaveURL(/\/login\/totp$/, { timeout: 10000 })

    await captureDocScreenshot(page, '04-totp-login.png')

    // Complete the login
    const code = await waitForFreshTOTPCode()
    const inputs = page.locator('input[inputmode="numeric"]')
    await expect(inputs).toHaveCount(6)
    for (let i = 0; i < 6; i++) {
      await inputs.nth(i).fill(code[i])
    }
    lastUsedTOTPCode = code
    await expect(page).toHaveURL(new RegExp(`^${BASE_URL}/?$`), { timeout: 15000 })

    // Obtain API tokens for subsequent authenticated screenshot tests
    await obtainFreshTokens()
  })

  // 05 — Fleet dashboard (empty state)
  test('05-fleet-dashboard', async ({ page }) => {
    await injectAuth(page)
    await expect(page.getByRole('heading', { name: 'Fleet Dashboard' })).toBeVisible({ timeout: 10000 })

    await captureDocScreenshot(page, '05-fleet-dashboard.png')
  })

  // 06 — Add Server modal
  test('06-add-server-modal', async ({ page }) => {
    await injectAuth(page)
    await expect(page.getByRole('heading', { name: 'Fleet Dashboard' })).toBeVisible({ timeout: 10000 })

    await page.getByRole('button', { name: 'Add Server' }).click()
    await expect(page.getByRole('heading', { name: 'Add Server' })).toBeVisible()

    await page.getByPlaceholder('e.g., web-prod-1').fill('web-prod-1')
    await page.getByRole('button', { name: 'Generate' }).click()

    await expect(page.locator('pre')).toBeVisible({ timeout: 10000 })

    await captureDocScreenshot(page, '06-add-server-modal.png')
  })

  // 07 — Audit logs
  test('07-audit-logs', async ({ page }) => {
    await injectAuth(page, '/audit-logs')
    await expect(page).toHaveURL(/\/audit-logs/, { timeout: 10000 })

    await expect(page.getByRole('heading', { name: 'Audit Logs' })).toBeVisible({ timeout: 10000 })

    // Wait for entries to load
    await expect(
      page.locator('table tbody tr').first()
    ).toBeVisible({ timeout: 10000 })

    await captureDocScreenshot(page, '07-audit-logs.png')
  })

  // 08 — Settings profile tab
  test('08-settings-profile', async ({ page }) => {
    await injectAuth(page, '/settings')
    await expect(page).toHaveURL(/\/settings/, { timeout: 10000 })
    await expect(page.getByText('admin').first()).toBeVisible({ timeout: 10000 })

    await captureDocScreenshot(page, '08-settings-profile.png')
  })

  // 09 — Settings users tab
  test('09-settings-users', async ({ page }) => {
    await injectAuth(page, '/settings?tab=users')
    await expect(page).toHaveURL(/\/settings/, { timeout: 10000 })
    await expect(page.getByText('User Management')).toBeVisible({ timeout: 10000 })
    await expect(page.locator('tr').filter({ hasText: 'admin' }).first()).toBeVisible({ timeout: 10000 })

    await captureDocScreenshot(page, '09-settings-users.png')
  })

  // 10 — Server detail file tree
  test('10-server-detail-filetree', async ({ page }) => {
    const server = await ensureDocsServerOnline()
    await page.setViewportSize({ width: 1400, height: 900 })
    await injectAuth(page, `/servers/${server.id}`)
    await expect(page.getByText(server.name).first()).toBeVisible({ timeout: 15000 })
    await expect(page.getByText('File Explorer')).toBeVisible({ timeout: 15000 })

    await captureDocScreenshot(page, '10-server-detail-filetree.png')
  })

  // 11 — Server detail dropzone
  test('11-server-detail-dropzone', async ({ page }) => {
    const server = await ensureDocsServerOnline()
    await page.setViewportSize({ width: 1400, height: 900 })
    await injectAuth(page, `/servers/${server.id}`)
    await expect(page.getByText(server.name).first()).toBeVisible({ timeout: 15000 })
    await page.getByRole('button', { name: 'Dropzone' }).click()
    await expect(page.getByText('Drop files here or click to browse')).toBeVisible({ timeout: 15000 })

    await captureDocScreenshot(page, '11-server-detail-dropzone.png')
  })

  // 12 — Settings notifications tab
  test('12-settings-notifications', async ({ page }) => {
    await injectAuth(page, '/settings?tab=notifications')
    await expect(page.getByText('SMTP Configuration')).toBeVisible({ timeout: 10000 })

    await captureDocScreenshot(page, '12-settings-notifications.png')
  })

  // 13 — Server detail terminal
  test('13-server-detail-terminal', async ({ page }) => {
    const server = await ensureDocsServerOnline()
    await page.setViewportSize({ width: 1400, height: 900 })
    await injectAuth(page, `/servers/${server.id}`)
    await expect(page.getByRole('button', { name: 'Terminal' })).toBeVisible({ timeout: 15000 })
    await page.getByRole('button', { name: 'Terminal' }).click()
    await expect(page.getByText('Live Terminal')).toBeVisible({ timeout: 15000 })
    await expect(page.getByText('Live shell ready')).toBeVisible({ timeout: 20000 })

    await captureDocScreenshot(page, '13-server-detail-terminal.png')
  })
})
