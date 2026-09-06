import { test, expect, APIRequestContext, Browser, BrowserContext, Page, request as apiRequest } from '@playwright/test'
import { authenticator } from 'otplib'
import { loadState, markTOTPCodeUsed, mintApiToken, waitForFreshTOTPCode } from './helpers'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:18081'

// Exact hub messages (spec 009, contracts/rest-api.md). The dashes are em
// dashes — keep them byte-for-byte.
const ENDED_MESSAGE = 'session ended — sign in again'
const EXPIRED_MESSAGE = 'session expired — sign in again'

const ADMIN_PASSWORD = 'E2eTestPass!2026'
const VIEWER_PASSWORD = 'E2eSessions!2026'

// The session half of the account policy this file starts from and restores.
const DEFAULT_SESSION_POLICY = { session_idle_minutes: 15, session_max_hours: 12 }

const POLICY_INPUT_IDS = {
  session_idle_minutes: 'policy-session-idle-minutes',
  session_max_hours: 'policy-session-max-hours',
} as const

type PolicyKey = keyof typeof POLICY_INPUT_IDS

interface HubConfig {
  session_idle_minutes: number
  session_max_hours: number
}

interface ApiUser {
  id: string
  username: string
}

interface ApiSession {
  id: string
  kind: 'web' | 'cli' | 'ssh' | 'terminal'
  ip?: string
  user_agent?: string
  created_at?: string
  last_seen_at?: string
  expires_at?: string
  idle_deadline_at?: string
  ended_at?: string
  end_reason?: string
  current?: boolean
  server?: string
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ---------------------------------------------------------------------------
// Credential budgeting
//
// The hub rate-limits POST /api/auth/login to 10 per IP per minute and
// POST /api/auth/login/totp to 3 — and every full sign-in spends one of each,
// so TOTP is the binding constraint for this file. First-login enrolment goes
// through POST /api/auth/totp/enable, which is setup-token protected and not
// rate limited, so it costs nothing here.
//
// awaitTotpBudget keeps this file at two verifications per rolling 65 s, which
// leaves one slot spare for a serial-group retry, and every credential call
// additionally retries a 429 rather than failing the test.
// ---------------------------------------------------------------------------

const totpCalls: number[] = []

async function awaitTotpBudget(): Promise<void> {
  for (;;) {
    const cutoff = Date.now() - 65_000
    while (totpCalls.length > 0 && totpCalls[0] < cutoff) totpCalls.shift()
    if (totpCalls.length < 2) return
    await sleep(Math.max(1_000, totpCalls[0] + 65_000 - Date.now()))
  }
}

/**
 * A TOTP code for `secret` that has not been used before.
 *
 * The admin's secret is shared with every other spec in the suite, so its
 * rotation is tracked by the module-level helper in helpers.ts; the throwaway
 * viewer's secret is private to this file and tracked here.
 */
const lastCodeBySecret = new Map<string, string>()

async function nextCode(secret: string, shared: boolean): Promise<string> {
  if (shared) {
    const code = await waitForFreshTOTPCode(secret)
    markTOTPCodeUsed(code)
    return code
  }
  const previous = lastCodeBySecret.get(secret)
  for (let i = 0; i < 40; i++) {
    const code = authenticator.generate(secret)
    if (code !== previous) {
      lastCodeBySecret.set(secret, code)
      return code
    }
    await sleep(1_000)
  }
  throw new Error('TOTP code did not rotate within 40s')
}

/**
 * Sign `username` in over the REST API and return the token pair. Used for the
 * sessions this file has to hold without a browser tab attached (an open
 * dashboard polls, which would keep an idle session alive).
 */
async function apiSignIn(
  username: string,
  password: string,
  secret: string,
  shared: boolean,
): Promise<{ access: string; refresh: string }> {
  const anon = await apiRequest.newContext({ baseURL: BASE_URL })
  try {
    let totpToken = ''
    for (let attempt = 0; attempt < 5 && !totpToken; attempt++) {
      const resp = await anon.post('/api/auth/login', { data: { username, password } })
      if (resp.status() === 429) {
        await sleep(20_000)
        continue
      }
      expect([200, 202], `password login for ${username}: ${await resp.text()}`).toContain(resp.status())
      totpToken = (await resp.json() as { totp_token: string }).totp_token
    }
    expect(totpToken, `password login for ${username} kept hitting the rate limiter`).toBeTruthy()

    for (let attempt = 0; attempt < 5; attempt++) {
      await awaitTotpBudget()
      const code = await nextCode(secret, shared)
      const resp = await anon.post('/api/auth/login/totp', { data: { totp_token: totpToken, code } })
      totpCalls.push(Date.now())
      if (resp.status() === 429) {
        await sleep(20_000)
        continue
      }
      expect(resp.status(), `totp verification for ${username}: ${await resp.text()}`).toBe(200)
      const pair = await resp.json() as { access_token: string; refresh_token: string }
      return { access: pair.access_token, refresh: pair.refresh_token }
    }
    throw new Error(`totp verification for ${username} kept hitting the rate limiter`)
  } finally {
    await anon.dispose()
  }
}

/** A Bearer-authenticated request context — one live session, no browser. */
async function bearerContext(accessToken: string): Promise<APIRequestContext> {
  return apiRequest.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${accessToken}` },
  })
}

/** Seed the SPA's auth cookies so a browser context carries an existing session. */
async function seedSessionCookies(context: BrowserContext, access: string, refresh: string) {
  const parsed = new URL(BASE_URL)
  const secure = parsed.protocol === 'https:'
  const expires = Math.floor(Date.now() / 1000)
  await context.addCookies([
    {
      name: 'veyport_access',
      value: access,
      domain: parsed.hostname,
      path: '/',
      expires: expires + 900,
      httpOnly: true,
      secure,
      sameSite: 'Strict',
    },
    {
      name: 'veyport_refresh',
      value: refresh,
      domain: parsed.hostname,
      path: '/api/auth/refresh',
      expires: expires + 604800,
      httpOnly: true,
      secure,
      sameSite: 'Strict',
    },
    {
      // Double-submit CSRF: the SPA echoes whatever the cookie holds, so any
      // value works as long as cookie and header agree.
      name: 'veyport_csrf',
      value: 'e2e-csrf',
      domain: parsed.hostname,
      path: '/',
      expires: expires + 604800,
      httpOnly: false,
      secure,
      sameSite: 'Strict',
    },
  ])
}

// ---------------------------------------------------------------------------
// Locators
// ---------------------------------------------------------------------------

/** The users table row for `username` (anchored, case-sensitive — see 07). */
function userRow(page: Page, username: string) {
  return page.locator('tbody tr').filter({
    hasText: new RegExp(`^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
  })
}

/**
 * The Sessions modal. Both it and the confirmation dialog it opens render as
 * `div.fixed.inset-0`, and the dialog is a child of the modal's root, so the
 * two are told apart by the width of their inner card (max-w-2xl vs max-w-sm)
 * rather than by text, which would match both.
 */
function sessionsModal(page: Page) {
  return page.locator('div.max-w-2xl')
}

function sessionRows(page: Page) {
  return sessionsModal(page).locator('tbody tr')
}

/** The ConfirmActionModal currently on screen, matched by its title. */
function confirmDialog(page: Page, title: string) {
  return page.locator('div.fixed.inset-0 > div.max-w-sm').filter({ hasText: title })
}

async function confirmAction(page: Page, title: string, body: string, confirmLabel: string) {
  const dialog = confirmDialog(page, title)
  await expect(dialog).toBeVisible({ timeout: 10_000 })
  await expect(dialog.getByText(body, { exact: true })).toBeVisible()
  await dialog.getByRole('button', { name: confirmLabel, exact: true }).click()
  await expect(dialog).toHaveCount(0, { timeout: 15_000 })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function listSessions(
  ctx: APIRequestContext,
  userId: string,
  includeEnded = false,
): Promise<ApiSession[]> {
  const resp = await ctx.get(`/api/users/${userId}/sessions${includeEnded ? '?include_ended=true' : ''}`)
  expect(resp.status(), await resp.text()).toBe(200)
  return (await resp.json() as { sessions: ApiSession[] }).sessions
}

async function putSessionPolicy(ctx: APIRequestContext, values: Record<string, number>) {
  const resp = await ctx.put('/api/settings/hub', { data: values })
  expect(resp.status(), await resp.text()).toBe(200)
  const echoed = await (await ctx.get('/api/settings/hub')).json() as HubConfig
  for (const [key, value] of Object.entries(values)) {
    expect(echoed[key as keyof HubConfig], `GET /api/settings/hub must echo ${key}`).toBe(value)
  }
}

/** Assert a session is refused with the exact hub message. */
async function expectRefused(ctx: APIRequestContext, expected: string, label: string) {
  const resp = await ctx.get('/api/auth/me')
  const text = await resp.text()
  expect(resp.status(), `${label}: ${text}`).toBe(401)
  expect((JSON.parse(text) as { error?: string }).error, label).toBe(expected)
}

async function expectLive(ctx: APIRequestContext, label: string) {
  const resp = await ctx.get('/api/auth/me')
  expect(resp.status(), `${label}: ${await resp.text()}`).toBe(200)
}

// ---------------------------------------------------------------------------
// Shared state
//
// Every test shares one throwaway viewer, the admin's browser session and the
// hub-wide session policy, so they must not interleave.
// ---------------------------------------------------------------------------

test.describe.configure({ mode: 'serial' })

// An API token, not a session: it is exempt from session validation, so policy
// changes and cleanup keep working across the deliberate expiries below.
let adminToken: APIRequestContext
let adminContext: BrowserContext
let adminPage: Page

let viewerUsername = ''
let viewerId = ''
let viewerSecret = ''

// Flow A/B share the viewer's first two sessions.
let v1Context: BrowserContext | undefined
let v1Page: Page | undefined
let v1Sid = ''
let v2Api: APIRequestContext | undefined
let v2Sid = ''

async function signInAdminBrowser(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const { totpSecret } = loadState()
  const pair = await apiSignIn('admin', ADMIN_PASSWORD, totpSecret, true)
  const context = await browser.newContext()
  await seedSessionCookies(context, pair.access, pair.refresh)
  const page = await context.newPage()
  await page.goto(BASE_URL + '/')
  return { context, page }
}

test.describe('Server-side sessions', () => {
  test.beforeAll(async ({ browser }) => {
    // The admin API token survives every session expiry this file provokes.
    const token = await mintApiToken('admin', `e2e-sessions-${Date.now()}`)
    expect(token).toMatch(/^adt_[0-9a-f]{64}$/)
    adminToken = await bearerContext(token)

    // Start from the shipped session policy whatever earlier specs left behind.
    await putSessionPolicy(adminToken, DEFAULT_SESSION_POLICY)

    const session = await signInAdminBrowser(browser)
    adminContext = session.context
    adminPage = session.page

    viewerUsername = `sess_${Date.now()}`
    const created = await adminToken.post('/api/users', {
      data: { username: viewerUsername, email: `${viewerUsername}@example.com`, role: 'viewer' },
    })
    expect(created.status(), await created.text()).toBe(201)
    const body = await created.json() as { user: ApiUser; temporary_password: string }
    viewerId = body.user.id

    // First sign-in in V1's own browser context: temporary password → forced
    // password change + TOTP enrolment. This is the file's only credential
    // form walkthrough; the later sign-ins go through the API so their timing
    // stays under the per-IP limiters.
    v1Context = await browser.newContext()
    v1Page = await v1Context.newPage()
    await v1Page.goto(BASE_URL + '/login')
    await v1Page.getByPlaceholder('username').fill(viewerUsername)
    await v1Page.getByPlaceholder('password').fill(body.temporary_password)
    await v1Page.getByRole('button', { name: 'Sign In' }).click()
    await expect(v1Page).toHaveURL(/\/setup\/totp$/, { timeout: 20_000 })

    await v1Page.getByPlaceholder('New password', { exact: true }).fill(VIEWER_PASSWORD)
    await v1Page.getByPlaceholder('Confirm new password').fill(VIEWER_PASSWORD)
    viewerSecret = (await v1Page.locator('code').first().textContent()) ?? ''
    expect(viewerSecret.length).toBeGreaterThan(10)
    const digits = v1Page.locator('input[inputmode="numeric"]')
    await expect(digits).toHaveCount(6)
    const enrolCode = authenticator.generate(viewerSecret)
    lastCodeBySecret.set(viewerSecret, enrolCode)
    for (let i = 0; i < 6; i++) {
      await digits.nth(i).fill(enrolCode[i])
    }
    await expect(v1Page).toHaveURL(new RegExp(`^${BASE_URL}/?$`), { timeout: 20_000 })
  })

  test.afterAll(async () => {
    if (adminToken) {
      await putSessionPolicy(adminToken, DEFAULT_SESSION_POLICY).catch(() => undefined)
      if (viewerId) await adminToken.delete(`/api/users/${viewerId}`)
    }
    if (v2Api) await v2Api.dispose()
    if (v1Context) await v1Context.close()
    if (adminContext) await adminContext.close()
    if (adminToken) await adminToken.dispose()
  })

  test('admin logs out one of two sessions', async () => {
    // A full API sign-in (which may wait out the TOTP limiter) plus a UI round
    // trip through the Sessions modal.
    test.setTimeout(240_000)

    // 1. The enrolment left exactly one live session: V1, the browser context.
    const before = await listSessions(adminToken, viewerId)
    expect(before, 'first sign-in must have created exactly one session').toHaveLength(1)
    expect(before[0].kind).toBe('web')
    v1Sid = before[0].id

    // 2. A second session for the same viewer, held in an API request context
    //    so nothing polls on its behalf.
    const pair = await apiSignIn(viewerUsername, VIEWER_PASSWORD, viewerSecret, false)
    v2Api = await bearerContext(pair.access)
    await expectLive(v2Api, 'V2 immediately after signing in')

    const both = await listSessions(adminToken, viewerId)
    expect(both).toHaveLength(2)
    v2Sid = (both.find(s => s.id !== v1Sid) as ApiSession).id
    expect(both.every(s => s.kind === 'web')).toBe(true)
    expect(both.every(s => Boolean(s.idle_deadline_at))).toBe(true)

    // 3. Settings → Users → the viewer's row → Sessions.
    await adminPage.goto(BASE_URL + '/settings?tab=users')
    await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 20_000 })
    await userRow(adminPage, viewerUsername).getByRole('button', { name: 'Sessions', exact: true }).click()

    const modal = sessionsModal(adminPage)
    await expect(modal.getByText(`Sessions — ${viewerUsername}`)).toBeVisible({ timeout: 15_000 })
    await expect(sessionRows(adminPage)).toHaveCount(2, { timeout: 15_000 })
    await expect(sessionRows(adminPage).filter({ hasText: 'Web' })).toHaveCount(2)

    // 4. Log out V2's row. The modal renders the list in the order the admin
    //    endpoint returns it, so the row index comes from the same endpoint —
    //    and which session actually ended is verified below rather than
    //    assumed, because the ordering key (last seen) can move under a
    //    polling browser tab.
    const ordered = await listSessions(adminToken, viewerId)
    const index = ordered.findIndex(s => s.id === v2Sid)
    expect(index, 'V2 must still be listed').toBeGreaterThanOrEqual(0)
    await sessionRows(adminPage).nth(index).getByRole('button', { name: 'Log out', exact: true }).click()
    await confirmAction(
      adminPage,
      'Log out session',
      `Log out this session for ${viewerUsername}? It ends immediately.`,
      'Log out',
    )
    await expect(sessionRows(adminPage)).toHaveCount(1, { timeout: 15_000 })

    // 5. Exactly one session ended, and it is the one the UI acted on.
    const all = await listSessions(adminToken, viewerId, true)
    const ended = all.filter(s => Boolean(s.ended_at))
    expect(ended, 'exactly one session must have ended').toHaveLength(1)
    expect([v1Sid, v2Sid]).toContain(ended[0].id)
    const endedV2 = ended[0].id === v2Sid

    // 6. The ended session is refused; the other one is untouched.
    if (endedV2) {
      await expectRefused(v2Api, ENDED_MESSAGE, 'V2 after the admin logged it out')
      await (v1Page as Page).goto(BASE_URL + '/settings')
      await expect(v1Page as Page).toHaveURL(/\/settings$/)
      await expect((v1Page as Page).getByText('Your sessions')).toBeVisible({ timeout: 20_000 })
    } else {
      await (v1Page as Page).goto(BASE_URL + '/')
      await expect(v1Page as Page).toHaveURL(/\/login$/, { timeout: 20_000 })
      await expectLive(v2Api, 'V2 after the admin logged out the other session')
    }
  })

  test('log out everywhere ends the rest', async () => {
    test.setTimeout(240_000)

    await adminPage.goto(BASE_URL + '/settings?tab=users')
    await expect(adminPage.getByText('User Management')).toBeVisible({ timeout: 20_000 })
    await userRow(adminPage, viewerUsername).getByRole('button', { name: 'Sessions', exact: true }).click()
    await expect(sessionRows(adminPage)).toHaveCount(1, { timeout: 15_000 })

    await sessionsModal(adminPage).getByRole('button', { name: 'Log out everywhere', exact: true }).click()
    await confirmAction(
      adminPage,
      'Log out everywhere',
      `Log out ${viewerUsername} everywhere? All web and CLI sessions end now and any open SSH shells are closed.`,
      'Log out everywhere',
    )
    await expect(sessionsModal(adminPage).getByText('No active sessions.')).toBeVisible({ timeout: 15_000 })

    expect(await listSessions(adminToken, viewerId), 'no live sessions may remain').toHaveLength(0)

    // Both of the viewer's sessions are now dead, whichever of them test A
    // ended: the browser lands on /login and the API context is refused.
    await (v1Page as Page).goto(BASE_URL + '/')
    await expect(v1Page as Page).toHaveURL(/\/login$/, { timeout: 20_000 })
    await expectRefused(v2Api as APIRequestContext, ENDED_MESSAGE, 'V2 after log out everywhere')
  })

  test('sign out other sessions from Profile', async ({ browser }) => {
    // Two full API sign-ins, each of which may wait out the TOTP limiter.
    test.setTimeout(240_000)

    const v3Pair = await apiSignIn(viewerUsername, VIEWER_PASSWORD, viewerSecret, false)
    const v3Context = await browser.newContext()
    await seedSessionCookies(v3Context, v3Pair.access, v3Pair.refresh)
    const v3Page = await v3Context.newPage()

    const v4Pair = await apiSignIn(viewerUsername, VIEWER_PASSWORD, viewerSecret, false)
    const v4Api = await bearerContext(v4Pair.access)
    await expectLive(v4Api, 'V4 immediately after signing in')

    try {
      expect(await listSessions(adminToken, viewerId)).toHaveLength(2)

      await v3Page.goto(BASE_URL + '/settings?tab=profile')
      await expect(v3Page.getByText('Your sessions')).toBeVisible({ timeout: 20_000 })
      const rows = v3Page.locator('table tbody tr')
      await expect(rows).toHaveCount(2, { timeout: 15_000 })
      await expect(rows.filter({ hasText: 'This session' })).toHaveCount(1)

      await v3Page.getByRole('button', { name: 'Sign out other sessions', exact: true }).click()
      await confirmAction(
        v3Page,
        'Sign out other sessions',
        'Sign out all other sessions? They end now and any open SSH shells are closed.',
        'Sign out',
      )

      await expect(v3Page.getByText('This is your only active session.')).toBeVisible({ timeout: 15_000 })
      await expectRefused(v4Api, ENDED_MESSAGE, 'V4 after the viewer signed out other sessions')

      const live = await listSessions(adminToken, viewerId)
      expect(live, 'only the calling session may survive').toHaveLength(1)
    } finally {
      await v4Api.dispose()
      await v3Context.close()
    }
  })

  test('account policy card round-trips the session fields', async () => {
    test.setTimeout(240_000)

    await adminPage.goto(BASE_URL + '/settings?tab=users')
    await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 20_000 })

    // Two minutes, not one: the hub throttles the last-seen write to 60 s and
    // evaluates the idle limit before touching, so a one-minute idle policy
    // would expire the admin's own browser session while this test is still
    // driving it. The one-minute case is exercised over the API in the idle
    // expiry test, which holds no browser session.
    const edited: Record<PolicyKey, number> = { session_idle_minutes: 2, session_max_hours: 1 }
    await savePolicy(adminPage, edited)

    await adminPage.reload()
    await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 20_000 })
    await expectPolicyValues(adminPage, edited)

    const cfg = await (await adminToken.get('/api/settings/hub')).json() as HubConfig
    expect(cfg.session_idle_minutes).toBe(2)
    expect(cfg.session_max_hours).toBe(1)

    await savePolicy(adminPage, DEFAULT_SESSION_POLICY)
    await adminPage.reload()
    await expect(adminPage.getByText('Account policy')).toBeVisible({ timeout: 20_000 })
    await expectPolicyValues(adminPage, DEFAULT_SESSION_POLICY)

    const restored = await (await adminToken.get('/api/settings/hub')).json() as HubConfig
    expect(restored.session_idle_minutes).toBe(DEFAULT_SESSION_POLICY.session_idle_minutes)
    expect(restored.session_max_hours).toBe(DEFAULT_SESSION_POLICY.session_max_hours)
  })

  // Runs last: a one-minute idle limit expires every live session on the hub,
  // the admin's browser session included, so nothing may depend on the UI
  // after this point. Cleanup runs on the admin API token, which is not a
  // session and is therefore unaffected.
  test('an unused session expires on the idle limit', async () => {
    test.setTimeout(240_000)

    await putSessionPolicy(adminToken, { session_idle_minutes: 1 })
    try {
      const pair = await apiSignIn(viewerUsername, VIEWER_PASSWORD, viewerSecret, false)
      const v5Api = await bearerContext(pair.access)
      try {
        await expectLive(v5Api, 'V5 immediately after signing in')

        // The viewer still owns the session test C signed in with, so V5 is
        // identified by its own self listing rather than by position.
        const mineResp = await v5Api.get('/api/auth/sessions')
        expect(mineResp.status(), await mineResp.text()).toBe(200)
        const mine = (await mineResp.json() as { sessions: ApiSession[] }).sessions
        const current = mine.find(s => s.current)
        expect(current, 'the caller\'s own session must be marked current').toBeTruthy()
        const v5 = current as ApiSession
        expect(v5.idle_deadline_at, 'a live session must carry an idle deadline').toBeTruthy()

        // No browser tab holds this session, so nothing refreshes it. The
        // reads above are throttled out of the last-seen write, so the idle
        // clock still runs from the moment the session was created.
        await sleep(65_000)

        await expectRefused(v5Api, EXPIRED_MESSAGE, 'V5 after the idle limit passed')

        const after = await listSessions(adminToken, viewerId, true)
        const row = after.find(s => s.id === v5.id)
        expect(row?.end_reason, 'the row must record why it ended').toBe('expired_idle')
      } finally {
        await v5Api.dispose()
      }
    } finally {
      await putSessionPolicy(adminToken, DEFAULT_SESSION_POLICY)
    }
  })
})

/** Fill Account policy fields and save, asserting the success state. */
async function savePolicy(page: Page, values: Partial<Record<PolicyKey, number>>) {
  for (const [key, value] of Object.entries(values) as [PolicyKey, number][]) {
    await page.locator(`#${POLICY_INPUT_IDS[key]}`).fill(String(value))
  }
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText('Account policy saved.')).toBeVisible({ timeout: 15_000 })
}

async function expectPolicyValues(page: Page, values: Partial<Record<PolicyKey, number>>) {
  for (const [key, value] of Object.entries(values) as [PolicyKey, number][]) {
    await expect(page.locator(`#${POLICY_INPUT_IDS[key]}`)).toHaveValue(String(value), { timeout: 15_000 })
  }
}
