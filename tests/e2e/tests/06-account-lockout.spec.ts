import { test, expect, APIRequestContext, Page } from '@playwright/test'
import { authenticator } from 'otplib'
import { adminApiContext } from './helpers'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:18081'

// The hub answers every locked sign-in stage with this exact string (spec 007,
// contracts/rest-api.md). The dash is an em dash — keep it byte-for-byte.
const LOCKED_MESSAGE = 'account temporarily locked — try again later'
const INVALID_MESSAGE = 'invalid credentials'

const WRONG_PASSWORD = 'WrongPassword!999'
const NEW_PASSWORD = 'E2eLockout!2026'

interface HubConfig {
  grpc_external_addr: string
  lockout_threshold: number
  lockout_window_minutes: number
  lockout_duration_minutes: number
}

interface ApiUser {
  id: string
  username: string
  failed_login_count: number
  last_failed_login_at?: string
  last_login_at?: string
  locked_until?: string
}

// The two tests share the hub's lockout policy and the per-IP login limiter, so
// they must not interleave.
test.describe.configure({ mode: 'serial' })

/**
 * Submit the credential form on /login and wait for the login call to land.
 * Returns the HTTP status so a test can distinguish 401 from 423 without
 * relying on the banner alone (the banner text is identical between two
 * consecutive wrong-password attempts).
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

async function putHubConfig(admin: APIRequestContext, cfg: Partial<HubConfig> & { grpc_external_addr: string }) {
  const resp = await admin.put('/api/settings/hub', { data: cfg })
  expect(resp.status(), await resp.text()).toBe(200)
}

async function getUser(admin: APIRequestContext, username: string): Promise<ApiUser> {
  const resp = await admin.get('/api/users')
  expect(resp.status(), await resp.text()).toBe(200)
  const body = await resp.json() as { users: ApiUser[] }
  const user = body.users.find(u => u.username === username)
  expect(user, `user ${username} missing from GET /api/users`).toBeTruthy()
  return user as ApiUser
}

test.describe('Account lockout', () => {
  test('locks after repeated failures, refuses the correct password, then auto-unlocks', async ({ browser }) => {
    // Three sign-in attempts, a ~60s wait for the lock to expire, and a
    // first-login TOTP enrolment all happen in this one test.
    test.setTimeout(150_000)

    const admin = await adminApiContext(BASE_URL)
    const suffix = Date.now()
    // The hub only accepts alphanumerics and underscores in usernames.
    const username = `lockme_${suffix}`
    let userId = ''
    let originalCfg: HubConfig | undefined

    const context = await browser.newContext()
    const page = await context.newPage()

    try {
      const cfgResp = await admin.get('/api/settings/hub')
      expect(cfgResp.status(), await cfgResp.text()).toBe(200)
      originalCfg = await cfgResp.json() as HubConfig

      // 1. Tighten the policy: lock on the 3rd failure, auto-unlock after 1 minute.
      // The hub now preserves an omitted grpc_external_addr on PUT, so echoing it
      // back here is belt-and-braces (kept for defense-in-depth against regressions).
      await putHubConfig(admin, {
        grpc_external_addr: originalCfg.grpc_external_addr,
        lockout_threshold: 3,
        lockout_duration_minutes: 1,
      })
      const echoed = await (await admin.get('/api/settings/hub')).json() as HubConfig
      expect(echoed.lockout_threshold).toBe(3)
      expect(echoed.lockout_duration_minutes).toBe(1)

      // 2. Create a throwaway viewer and keep its temporary password.
      const created = await admin.post('/api/users', {
        data: { username, email: `${username}@example.com`, role: 'viewer' },
      })
      expect(created.status(), await created.text()).toBe(201)
      const createdBody = await created.json() as { user: ApiUser; temporary_password: string }
      userId = createdBody.user.id
      const tempPassword = createdBody.temporary_password
      expect(tempPassword.length).toBeGreaterThan(8)

      // 3. Three wrong passwords lock the account; the correct password is then
      //    refused with 423 and the lock message, still on the credential step.
      await page.goto(BASE_URL + '/login')
      await expect(page).toHaveURL(/\/login$/)

      for (let attempt = 1; attempt <= 3; attempt++) {
        const status = await submitCredentials(page, username, WRONG_PASSWORD)
        expect(status, `attempt ${attempt} should be rejected as a bad credential`).toBe(401)
        await expect(page.getByText(INVALID_MESSAGE)).toBeVisible({ timeout: 10000 })
      }

      const lockedStatus = await submitCredentials(page, username, tempPassword)
      expect(lockedStatus, 'the correct password must be refused while locked').toBe(423)
      await expect(page.getByText(LOCKED_MESSAGE)).toBeVisible({ timeout: 10000 })
      await expect(page).toHaveURL(/\/login$/)

      // 4. The admin view shows the streak and the lock.
      const locked = await getUser(admin, username)
      expect(locked.failed_login_count).toBe(3)
      expect(locked.locked_until).toBeTruthy()
      const lockedUntil = new Date(locked.locked_until as string).getTime()
      expect(lockedUntil).toBeGreaterThan(Date.now())
      expect(locked.last_failed_login_at).toBeTruthy()

      // 5. Wait out the one-minute lock (plus a small margin).
      const remainingMs = lockedUntil - Date.now() + 3000
      expect(remainingMs).toBeLessThan(90_000)
      await page.waitForTimeout(Math.max(remainingMs, 1000))

      // 6. The same password now works: the account has no TOTP yet, so the app
      //    moves on to first-login enrolment instead of staying on /login.
      const unlockedStatus = await submitCredentials(page, username, tempPassword)
      expect(unlockedStatus, 'the lock must expire on its own').toBe(200)
      await expect(page).not.toHaveURL(/\/login$/)
      await expect(page.getByText(LOCKED_MESSAGE)).toHaveCount(0)
      await expect(page).toHaveURL(/\/setup\/totp$/, { timeout: 10000 })

      // Finish the first sign-in (new password + TOTP) so the hub records a
      // completed login — that is what clears the failure streak.
      await page.getByPlaceholder('New password', { exact: true }).fill(NEW_PASSWORD)
      await page.getByPlaceholder('Confirm new password').fill(NEW_PASSWORD)
      const secret = (await page.locator('code').first().textContent()) ?? ''
      expect(secret.length).toBeGreaterThan(10)
      const digits = page.locator('input[inputmode="numeric"]')
      await expect(digits).toHaveCount(6)
      const code = authenticator.generate(secret)
      for (let i = 0; i < 6; i++) {
        await digits.nth(i).fill(code[i])
      }
      await expect(page).toHaveURL(new RegExp(`^${BASE_URL}/?$`), { timeout: 15000 })

      // 7. A completed sign-in resets the counter and clears the lock.
      const after = await getUser(admin, username)
      expect(after.failed_login_count).toBe(0)
      expect(after.last_login_at).toBeTruthy()
      if (after.locked_until) {
        expect(new Date(after.locked_until).getTime()).toBeLessThanOrEqual(Date.now())
      }
    } finally {
      if (originalCfg) {
        await admin.put('/api/settings/hub', {
          data: {
            grpc_external_addr: originalCfg.grpc_external_addr,
            lockout_threshold: originalCfg.lockout_threshold,
            lockout_window_minutes: originalCfg.lockout_window_minutes,
            lockout_duration_minutes: originalCfg.lockout_duration_minutes,
          },
        })
      }
      if (userId) {
        await admin.delete(`/api/users/${userId}`)
      }
      await context.close()
      await admin.dispose()
    }
  })

  test('unknown usernames are never locked', async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()

    try {
      const username = `ghost_${Date.now()}`
      await page.goto(BASE_URL + '/login')

      // Well past the default threshold for a real account: an unknown name has
      // no row to count against, so every attempt stays a plain 401.
      for (let attempt = 1; attempt <= 4; attempt++) {
        const status = await submitCredentials(page, username, WRONG_PASSWORD)
        expect(status, `attempt ${attempt} on an unknown username`).toBe(401)
        await expect(page.getByText(INVALID_MESSAGE)).toBeVisible({ timeout: 10000 })
        await expect(page.getByText(LOCKED_MESSAGE)).toHaveCount(0)
      }
    } finally {
      await context.close()
    }
  })
})
