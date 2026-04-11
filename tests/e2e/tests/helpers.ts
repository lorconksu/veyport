import { Page } from '@playwright/test'
import { authenticator } from 'otplib'
import fs from 'fs'
import path from 'path'

// Path for persisting TOTP secret across test specs
const STATE_FILE = path.resolve(__dirname, '../.e2e-state.json')

interface E2EState {
  totpSecret: string
}

export function saveState(state: E2EState) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2))
}

export function loadState(): E2EState {
  if (!fs.existsSync(STATE_FILE)) {
    throw new Error('E2E state file not found — run 01-setup-flow.spec.ts first')
  }
  return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')) as E2EState
}

// Track the last used TOTP code to avoid replay rejection
let lastUsedTOTPCode = ''

export function getTOTPCode(secret: string): string {
  return authenticator.generate(secret)
}

/**
 * Wait until the TOTP code changes from the last used one.
 * Prevents replay rejection when multiple tests use TOTP in the same 30s window.
 */
export async function waitForFreshTOTPCode(secret: string): Promise<string> {
  if (!lastUsedTOTPCode) return authenticator.generate(secret)
  for (let i = 0; i < 35; i++) {
    const code = authenticator.generate(secret)
    if (code !== lastUsedTOTPCode) return code
    await new Promise(r => setTimeout(r, 1000))
  }
  throw new Error('TOTP code did not rotate within 35s')
}

export function markTOTPCodeUsed(code: string) {
  lastUsedTOTPCode = code
}

export async function loginViaAPI(page: Page, baseURL: string) {
  const { totpSecret } = loadState()

  // Step 1: Password login
  const loginResp = await page.request.post(`${baseURL}/api/auth/login`, {
    data: { username: 'admin', password: 'E2eTestPass!2026' },
  })
  if (!loginResp.ok()) {
    throw new Error(`password login failed: ${loginResp.status()} ${await loginResp.text()}`)
  }
  const loginData = await loginResp.json() as { totp_token: string }

  // Step 2: TOTP verification - wait for a fresh code to avoid replay rejection
  const code = await waitForFreshTOTPCode(totpSecret)
  const totpResp = await page.request.post(`${baseURL}/api/auth/login/totp`, {
    data: { totp_token: loginData.totp_token, code },
  })
  if (!totpResp.ok()) {
    throw new Error(`totp login failed: ${totpResp.status()} ${await totpResp.text()}`)
  }
  lastUsedTOTPCode = code
  const authData = await totpResp.json() as { access_token: string; refresh_token: string }

  // Step 3: Inject tokens into localStorage so the SPA picks them up
  // Navigate to a blank page first to set localStorage without redirect interference
  await page.goto(baseURL + '/api/auth/status')
  await page.evaluate((tokens) => {
    localStorage.setItem('aerodocs_access_token', tokens.access_token)
    localStorage.setItem('aerodocs_refresh_token', tokens.refresh_token)
  }, authData)

  // Now navigate to the app — tokens are in localStorage, so auth will succeed
  await page.goto(baseURL + '/')
}
