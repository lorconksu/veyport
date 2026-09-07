import { test, expect, APIRequestContext, Browser, BrowserContext, Page, request as apiRequest } from '@playwright/test'
import { authenticator } from 'otplib'
import { loadState, markTOTPCodeUsed, mintApiToken, waitForFreshTOTPCode } from './helpers'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:18081'

// Exact hub messages (spec 008, contracts/rest-api.md). The dashes are em
// dashes — keep them byte-for-byte.
const DISABLED_MESSAGE = 'account disabled — contact an administrator'
const INVALID_MESSAGE = 'invalid credentials'

const ADMIN_PASSWORD = 'E2eTestPass!2026'
const WRONG_PASSWORD = 'WrongPassword!999'
const VIEWER_PASSWORD = 'E2eLifecycle!2026'

// Policy defaults the hub ships with; restored in afterAll.
const DEFAULT_POLICY = {
  lockout_threshold: 5,
  lockout_window_minutes: 15,
  lockout_duration_minutes: 15,
  dormant_days: 35,
}

const POLICY_INPUT_IDS = {
  lockout_threshold: 'policy-lockout-threshold',
  lockout_window_minutes: 'policy-lockout-window-minutes',
  lockout_duration_minutes: 'policy-lockout-duration-minutes',
  dormant_days: 'policy-dormant-days',
} as const

type PolicyKey = keyof typeof POLICY_INPUT_IDS

interface HubConfig {
  grpc_external_addr: string
  lockout_threshold: number
  lockout_window_minutes: number
  lockout_duration_minutes: number
  dormant_days: number
}

interface ApiUser {
  id: string
  username: string
  role: string
  status?: string
  dormancy_exempt?: boolean
  failed_login_count?: number
  locked_until?: string
}

// Every test in this file shares one admin browser session, one throwaway
// viewer and the hub-wide account policy, so they must not interleave.
test.describe.configure({ mode: 'serial' })

/**
 * Submit the credential form on /login and return the HTTP status of the login
 * call, so a test can tell 401 (bad password) from 403 (account state) and 423
 * (locked) without relying on the banner alone.
 */
async function submitCredentials(page: Page, username: string, password: string): Promise<number> {
  await page.getByPlaceholder('username').fill(username)
  await page.getByPlaceholder('password').fill(password)
  const [response] = await Promise.all([
    page.waitForResponse(
      r => r.url().endsWith('/api/auth/login') && r.request().method() === 'POST',
      { timeout: 15000 },
    ),
    page.getByRole('button', { name: 'Sign In' }).click(),
  ])
  return response.status()
}

/**
 * The users table row for `username`. Anchored, case-sensitive regex: a plain
 * `hasText` string matches case-insensitively anywhere in the row, so "admin"
 * would also match every row whose role <select> lists an "Admin" option.
 */
function userRow(page: Page, username: string) {
  return page.locator('tbody tr').filter({ hasText: new RegExp(`^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`) })
}

/**
 * Click a row action, then confirm it in the ConfirmActionModal. The modal is
 * matched by its title so the row's own button (same label) is never hit twice.
 */
async function rowActionWithConfirm(
  page: Page,
  username: string,
  actionLabel: string,
  modalTitle: string,
  confirmLabel: string,
) {
  await userRow(page, username).getByRole('button', { name: actionLabel, exact: true }).click()
  const modal = page.locator('div.fixed.inset-0').filter({ hasText: modalTitle })
  await expect(modal).toBeVisible({ timeout: 10000 })
  await modal.getByRole('button', { name: confirmLabel, exact: true }).click()
  await expect(modal).toHaveCount(0, { timeout: 15000 })
}

/** Fill the Account policy card fields and save, asserting the success state. */
async function savePolicy(page: Page, values: Partial<Record<PolicyKey, number>>) {
  for (const [key, value] of Object.entries(values) as [PolicyKey, number][]) {
    await page.locator(`#${POLICY_INPUT_IDS[key]}`).fill(String(value))
  }
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText('Account policy saved.')).toBeVisible({ timeout: 15000 })
}

async function expectPolicyValues(page: Page, values: Partial<Record<PolicyKey, number>>) {
  for (const [key, value] of Object.entries(values) as [PolicyKey, number][]) {
    await expect(page.locator(`#${POLICY_INPUT_IDS[key]}`)).toHaveValue(String(value), { timeout: 15000 })
  }
}

/**
 * Sign the admin in ONCE and hand back both a Bearer-authenticated API context
 * and a browser context whose cookies carry the same session.
 *
 * The 007 helpers offer adminApiContext and loginViaAPI, but using both would
 * spend two POST /api/auth/login and two POST /api/auth/login/totp calls. This
 * file also submits seven viewer credentials, and the hub allows 10 logins and
 * 3 TOTP verifications per IP per minute — so one shared sign-in keeps the
 * whole file inside budget even when a failure triggers a serial-group retry.
 */
async function signInAdmin(browser: Browser): Promise<{
  api: APIRequestContext
  context: BrowserContext
  page: Page
}> {
  const { totpSecret } = loadState()

  let accessToken = ''
  let refreshToken = ''
  const anon = await apiRequest.newContext({ baseURL: BASE_URL })
  try {
    const loginResp = await anon.post('/api/auth/login', {
      data: { username: 'admin', password: ADMIN_PASSWORD },
    })
    if (!loginResp.ok()) {
      throw new Error(`admin password login failed: ${loginResp.status()} ${await loginResp.text()}`)
    }
    const { totp_token: totpToken } = await loginResp.json() as { totp_token: string }

    const code = await waitForFreshTOTPCode(totpSecret)
    const totpResp = await anon.post('/api/auth/login/totp', { data: { totp_token: totpToken, code } })
    markTOTPCodeUsed(code)
    if (!totpResp.ok()) {
      throw new Error(`admin totp login failed: ${totpResp.status()} ${await totpResp.text()}`)
    }
    const pair = await totpResp.json() as { access_token: string; refresh_token: string }
    accessToken = pair.access_token
    refreshToken = pair.refresh_token
  } finally {
    await anon.dispose()
  }

  // Bearer requests skip the double-submit CSRF check, so this context can
  // issue mutating admin calls directly.
  const api = await apiRequest.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${accessToken}` },
  })

  const context = await browser.newContext()
  const page = await context.newPage()
  const parsedBaseURL = new URL(BASE_URL)
  const secure = parsedBaseURL.protocol === 'https:'
  const expires = Math.floor(Date.now() / 1000)
  await context.addCookies([
    {
      name: 'veyport_access',
      value: accessToken,
      domain: parsedBaseURL.hostname,
      path: '/',
      expires: expires + 900,
      httpOnly: true,
      secure,
      sameSite: 'Strict',
    },
    {
      name: 'veyport_refresh',
      value: refreshToken,
      domain: parsedBaseURL.hostname,
      path: '/api/auth/refresh',
      expires: expires + 604800,
      httpOnly: true,
      secure,
      sameSite: 'Strict',
    },
    {
      name: 'veyport_csrf',
      value: 'e2e-csrf',
      domain: parsedBaseURL.hostname,
      path: '/',
      expires: expires + 604800,
      httpOnly: false,
      secure,
      sameSite: 'Strict',
    },
  ])
  await page.goto(BASE_URL + '/')

  return { api, context, page }
}

async function getUsers(admin: APIRequestContext): Promise<ApiUser[]> {
  const resp = await admin.get('/api/users')
  expect(resp.status(), await resp.text()).toBe(200)
  return (await resp.json() as { users: ApiUser[] }).users
}

async function getUser(admin: APIRequestContext, username: string): Promise<ApiUser> {
  const user = (await getUsers(admin)).find(u => u.username === username)
  expect(user, `user ${username} missing from GET /api/users`).toBeTruthy()
  return user as ApiUser
}

// Shared across the serial tests.
let admin: APIRequestContext
let adminContext: BrowserContext
let adminPage: Page
let viewerUsername = ''
let viewerId = ''
let viewerTempPassword = ''
let originalCfg: HubConfig | undefined

test.describe('Account lifecycle', () => {
  test.beforeAll(async ({ browser }) => {
    const session = await signInAdmin(browser)
    admin = session.api
    adminContext = session.context
    adminPage = session.page

    const cfgResp = await admin.get('/api/settings/hub')
    expect(cfgResp.status(), await cfgResp.text()).toBe(200)
    originalCfg = await cfgResp.json() as HubConfig

    // Throwaway viewer. The hub only accepts alphanumerics and underscores.
    viewerUsername = `lc_${Date.now()}`
    const created = await admin.post('/api/users', {
      data: { username: viewerUsername, email: `${viewerUsername}@example.com`, role: 'viewer' },
    })
    expect(created.status(), await created.text()).toBe(201)
    const createdBody = await created.json() as { user: ApiUser; temporary_password: string }
    viewerId = createdBody.user.id
    viewerTempPassword = createdBody.temporary_password
    expect(viewerTempPassword.length).toBeGreaterThan(8)

  })

  test.afterAll(async () => {
    if (adminPage && originalCfg) {
      // Restore the policy through the API — cheaper and more reliable than the
      // card when a test failed midway.
      await admin.put('/api/settings/hub', {
        data: {
          grpc_external_addr: originalCfg.grpc_external_addr,
          lockout_threshold: originalCfg.lockout_threshold,
          lockout_window_minutes: originalCfg.lockout_window_minutes,
          lockout_duration_minutes: originalCfg.lockout_duration_minutes,
          dormant_days: originalCfg.dormant_days,
        },
      })
    }
    if (viewerId) {
      await admin.delete(`/api/users/${viewerId}`)
    }
    if (adminContext) await adminContext.close()
    if (admin) await admin.dispose()
  })

  test('disable ends sessions and tokens, enable restores access', async ({ browser }) => {
    // A first sign-in with TOTP enrolment, an API-token round trip and three
    // more credential submissions all happen in this one test.
    test.setTimeout(180_000)

    const viewerContext = await browser.newContext()
    const viewerPage = await viewerContext.newPage()
    let tokenContext: APIRequestContext | undefined

    try {
      // 1. The viewer completes its first sign-in in its own browser context:
      //    temporary password → forced password change + TOTP enrolment.
      await viewerPage.goto(BASE_URL + '/login')
      const firstStatus = await submitCredentials(viewerPage, viewerUsername, viewerTempPassword)
      expect(firstStatus, 'first sign-in with the temporary password').toBe(200)
      await expect(viewerPage).toHaveURL(/\/setup\/totp$/, { timeout: 15000 })

      await viewerPage.getByPlaceholder('New password', { exact: true }).fill(VIEWER_PASSWORD)
      await viewerPage.getByPlaceholder('Confirm new password').fill(VIEWER_PASSWORD)
      const secret = (await viewerPage.locator('code').first().textContent()) ?? ''
      expect(secret.length).toBeGreaterThan(10)
      const digits = viewerPage.locator('input[inputmode="numeric"]')
      await expect(digits).toHaveCount(6)
      const code = authenticator.generate(secret)
      for (let i = 0; i < 6; i++) {
        await digits.nth(i).fill(code[i])
      }
      // Lands on the dashboard with a live session.
      await expect(viewerPage).toHaveURL(new RegExp(`^${BASE_URL}/?$`), { timeout: 20000 })

      // 2. Mint an API token for the viewer and prove it works.
      const token = await mintApiToken(viewerUsername)
      expect(token, 'the admin CLI must print a full token, not the display prefix').toMatch(/^adt_[0-9a-f]{64}$/)
      tokenContext = await apiRequest.newContext({
        baseURL: BASE_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` },
      })
      const before = await tokenContext.get('/api/servers')
      expect(before.status(), await before.text()).toBe(200)

      // 3. The admin disables the account from Settings → Users.
      await adminPage.goto(BASE_URL + '/settings?tab=users')
      await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 15000 })
      const row = userRow(adminPage, viewerUsername)
      await expect(row).toBeVisible({ timeout: 15000 })
      await rowActionWithConfirm(adminPage, viewerUsername, 'Disable', 'Disable User', 'Disable')
      await expect(row.getByText('Disabled', { exact: true })).toBeVisible({ timeout: 15000 })

      // 4. The viewer's live session dies on its next request.
      await viewerPage.goto(BASE_URL + '/')
      await expect(viewerPage).toHaveURL(/\/login$/, { timeout: 20000 })

      // 5. The API token no longer grants access.
      //
      //    Disabling revokes the account's API tokens outright, so the hub can
      //    no longer attribute this token to a user and the auth middleware
      //    answers with the generic "invalid token" rather than the
      //    account-state message. That matches the hub's own
      //    integration/account_lifecycle_test.go, which asserts only the 401
      //    here and reserves the account message for the dormant case, where
      //    tokens are not revoked. Either body is accepted; the 401 is the
      //    security-relevant fact.
      const afterDisable = await tokenContext.get('/api/servers')
      expect(afterDisable.status()).toBe(401)
      const afterBody = await afterDisable.json() as { error?: string }
      expect([DISABLED_MESSAGE, 'invalid token']).toContain(afterBody.error)

      // 6. A fresh sign-in with the correct password is refused with 403 and
      //    the message renders verbatim in the banner; no navigation.
      const disabledStatus = await submitCredentials(viewerPage, viewerUsername, VIEWER_PASSWORD)
      expect(disabledStatus, 'a disabled account must be refused before the password check').toBe(403)
      await expect(viewerPage.getByText(DISABLED_MESSAGE)).toBeVisible({ timeout: 10000 })
      await expect(viewerPage).toHaveURL(/\/login$/)

      const disabled = await getUser(admin, viewerUsername)
      expect(disabled.status).toBe('disabled')

      // 7. Enable restores access.
      await rowActionWithConfirm(adminPage, viewerUsername, 'Enable', 'Enable User', 'Enable')
      await expect(row.getByText('Disabled', { exact: true })).toHaveCount(0, { timeout: 15000 })
      await expect(row.getByText('Active', { exact: true })).toBeVisible({ timeout: 15000 })

      // 8. The same password now gets past the credential stage. TOTP is
      //    enrolled, so the app moves on to the code page instead of the
      //    dashboard.
      // 202 Accepted is the hub's existing "password accepted, TOTP required"
      // response; 200 is only returned when TOTP still has to be enrolled.
      const enabledStatus = await submitCredentials(viewerPage, viewerUsername, VIEWER_PASSWORD)
      expect(enabledStatus, 'an enabled account must sign in again').toBe(202)
      await expect(viewerPage).toHaveURL(/\/login\/totp$/, { timeout: 15000 })
      await expect(viewerPage.getByText(DISABLED_MESSAGE)).toHaveCount(0)
    } finally {
      if (tokenContext) await tokenContext.dispose()
      await viewerContext.close()
    }
  })

  test('admin unlock releases a locked account', async ({ browser }) => {
    // Three wrong passwords, an unlock round trip and a final sign-in.
    test.setTimeout(180_000)

    const viewerContext = await browser.newContext()
    const viewerPage = await viewerContext.newPage()

    try {
      // 0. Let the per-IP login limiter (10 per sliding 60s) drain. The
      //    previous test spends three credential submissions, and this one
      //    needs four back to back; without the pause the burst is answered
      //    with 429 instead of 401.
      await adminPage.waitForTimeout(62_000)

      // 1. Tighten the policy through the Account policy card: lock on the 3rd
      //    failure, and keep the default 15-minute lock so it cannot expire
      //    underneath the test.
      await adminPage.goto(BASE_URL + '/settings?tab=users')
      await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 15000 })
      await savePolicy(adminPage, { lockout_threshold: 3, lockout_duration_minutes: 15 })

      // 2. Three wrong passwords lock the viewer.
      await viewerPage.goto(BASE_URL + '/login')
      for (let attempt = 1; attempt <= 3; attempt++) {
        const status = await submitCredentials(viewerPage, viewerUsername, WRONG_PASSWORD)
        expect(status, `attempt ${attempt} should be a plain bad credential`).toBe(401)
        await expect(viewerPage.getByText(INVALID_MESSAGE)).toBeVisible({ timeout: 10000 })
      }

      const locked = await getUser(admin, viewerUsername)
      expect(locked.status).toBe('locked')
      expect(locked.locked_until).toBeTruthy()

      // 3. The admin sees the lock and clears it.
      await adminPage.reload()
      await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 15000 })
      const row = userRow(adminPage, viewerUsername)
      await expect(row.getByText(/^Locked until \d{2}:\d{2}$/)).toBeVisible({ timeout: 15000 })

      await rowActionWithConfirm(adminPage, viewerUsername, 'Unlock', 'Unlock User', 'Unlock')
      await expect(row.getByText(/^Locked/)).toHaveCount(0, { timeout: 15000 })
      await expect(row.getByText('Active', { exact: true })).toBeVisible({ timeout: 15000 })

      const unlocked = await getUser(admin, viewerUsername)
      expect(unlocked.status).toBe('active')
      expect(unlocked.failed_login_count ?? 0).toBe(0)

      // 4. The correct password works again straight away.
      const status = await submitCredentials(viewerPage, viewerUsername, VIEWER_PASSWORD)
      expect(status, 'an unlocked account must sign in immediately').toBe(202)
      await expect(viewerPage).toHaveURL(/\/login\/totp$/, { timeout: 15000 })
    } finally {
      await viewerContext.close()
    }
  })

  test('account policy card round-trips every field', async () => {
    test.setTimeout(120_000)

    await adminPage.goto(BASE_URL + '/settings?tab=users')
    await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 15000 })

    const edited = {
      lockout_threshold: 4,
      lockout_window_minutes: 20,
      lockout_duration_minutes: 2,
      dormant_days: 1,
    }
    await savePolicy(adminPage, edited)

    // Values survive a full reload (they come back from GET /api/settings/hub).
    await adminPage.reload()
    await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 15000 })
    await expectPolicyValues(adminPage, edited)

    const cfg = await (await admin.get('/api/settings/hub')).json() as HubConfig
    expect(cfg.lockout_threshold).toBe(4)
    expect(cfg.lockout_window_minutes).toBe(20)
    expect(cfg.lockout_duration_minutes).toBe(2)
    expect(cfg.dormant_days).toBe(1)

    // Put the shipped defaults back and confirm they stuck.
    await savePolicy(adminPage, DEFAULT_POLICY)
    await adminPage.reload()
    await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 15000 })
    await expectPolicyValues(adminPage, DEFAULT_POLICY)

    const restored = await (await admin.get('/api/settings/hub')).json() as HubConfig
    expect(restored.dormant_days).toBe(DEFAULT_POLICY.dormant_days)
    expect(restored.lockout_threshold).toBe(DEFAULT_POLICY.lockout_threshold)
  })

  test('the first administrator is exempt from dormancy', async () => {
    test.setTimeout(120_000)

    await adminPage.goto(BASE_URL + '/settings?tab=users')
    await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 15000 })

    const row = userRow(adminPage, 'admin')
    await expect(row.getByText('Never dormant', { exact: true })).toBeVisible({ timeout: 15000 })

    const adminUser = await getUser(admin, 'admin')
    expect(adminUser.dormancy_exempt).toBe(true)

    // The row actions are hidden on the viewer's own row, so drive the toggle
    // through the API and check that the marker follows. (The endpoint audits
    // both directions server-side; that is covered by the Go tests.)
    const cleared = await admin.put(`/api/users/${adminUser.id}/dormancy-exemption`, { data: { exempt: false } })
    expect(cleared.status(), await cleared.text()).toBe(200)
    await adminPage.reload()
    await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 15000 })
    await expect(userRow(adminPage, 'admin').getByText('Never dormant', { exact: true })).toHaveCount(0, { timeout: 15000 })

    const restored = await admin.put(`/api/users/${adminUser.id}/dormancy-exemption`, { data: { exempt: true } })
    expect(restored.status(), await restored.text()).toBe(200)
    await adminPage.reload()
    await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 15000 })
    await expect(userRow(adminPage, 'admin').getByText('Never dormant', { exact: true })).toBeVisible({ timeout: 15000 })
  })
})
