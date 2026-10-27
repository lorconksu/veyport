import { test, expect, type Page } from '@playwright/test'
import { authenticator } from 'otplib'
import { execFileSync } from 'node:child_process'
import { loginViaAPI } from './helpers'

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:18081'
const initialPassword = 'E2eAccountInitial!2026'
const permanentPassword = 'E2eAccountRecovered!2026'

// Credentials are deliberately shown in this journey. No trace, video or
// screenshots may capture the one-time result or the enrollment secret.
test.use({ trace: 'off', screenshot: 'off', video: 'off' })
test.describe.configure({ mode: 'serial' })

function row(page: Page, username: string) {
  return page.locator('tbody tr').filter({ has: page.getByRole('cell', { name: username, exact: true }) })
}

async function signIn(page: Page, username: string, password: string) {
  await page.goto(baseURL + '/login')
  await page.getByPlaceholder('username').fill(username)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: 'Sign In', exact: true }).click()
}

async function nextCode(page: Page, secret: string, previous: string) {
  await expect.poll(() => authenticator.generate(secret) !== previous, { timeout: 40_000, intervals: [1000] }).toBe(true)
  return authenticator.generate(secret)
}

// A private fixture-only connection ages precisely one disposable local user.
// It shares the e2e volume, never changes the running hub image or its schema,
// and binds every value rather than interpolating SQL identifiers or values.
function seedAccountFixtures(local: string, ldap: string, unknown: string) {
  for (const username of [local, ldap, unknown]) {
    if (!/^am_[0-9]+_(local|ldap|unknown)$/.test(username)) throw new Error('Refusing non-fixture username')
  }
  const container = process.env.E2E_CONTAINER || 'veyport-e2e'
  if (container !== 'veyport-e2e') throw new Error('Fixture seeding requires the disposable veyport-e2e container')
  const script = `import sqlite3,sys
local,ldap,unknown=sys.argv[1:]
db=sqlite3.connect('/data/veyport.db',timeout=15)
with db:
 for username in (local,ldap,unknown):
  assert db.execute('SELECT role,auth_provider FROM users WHERE username=?',(username,)).fetchone()==('viewer','local')
 assert db.execute("UPDATE users SET created_at=?,last_login_at=NULL,last_activity_at=NULL,reactivated_at=NULL WHERE username=?",('2000-01-01 00:00:00',local)).rowcount==1
 assert db.execute('UPDATE users SET auth_provider=? WHERE username=?',('ldap',ldap)).rowcount==1
 assert db.execute('UPDATE users SET auth_provider=? WHERE username=?',('unknown-fixture',unknown)).rowcount==1
db.close()`
  execFileSync('docker', ['run', '--rm', '--volumes-from', container, '--network', 'none', 'python:3-alpine', 'python', '-c', script, local, ldap, unknown], { stdio: 'pipe', timeout: 120_000 })
}

test('source ownership, direct dormant reactivation and existing-MFA local recovery require fresh sign-in', async ({ browser }) => {
  test.setTimeout(300_000)
  const adminContext = await browser.newContext()
  const viewerContext = await browser.newContext()
  const adminPage = await adminContext.newPage()
  const viewerPage = await viewerContext.newPage()
  const prefix = `am_${Date.now()}`
  const usernames = [`${prefix}_local`, `${prefix}_ldap`, `${prefix}_unknown`]
  const createdIds: string[] = []
  let csrf = ''
  try {
    // Other serial files share the hub's per-IP login/TOTP limiters.
    await adminPage.waitForTimeout(62_000)
    await loginViaAPI(adminPage, baseURL)
    csrf = (await adminContext.cookies()).find(cookie => cookie.name === '__Host-veyport_csrf')?.value ?? ''
    const headers = { 'X-CSRF-Token': csrf }
    let initialTemporaryPassword = ''
    for (const username of usernames) {
      const response = await adminPage.request.post(baseURL + '/api/users', { headers, data: { username, email: `${username}@example.test`, role: 'viewer' } })
      expect(response.status()).toBe(201)
      const body = await response.json() as { user: { id: string }; temporary_password: string }
      createdIds.push(body.user.id)
      if (username === usernames[0]) initialTemporaryPassword = body.temporary_password
    }
    seedAccountFixtures(...usernames as [string, string, string])
    await adminPage.goto(baseURL + '/settings?tab=users')
    await expect(adminPage.getByRole('columnheader', { name: 'Account source' })).toBeVisible()
    const localRow = row(adminPage, usernames[0])
    await expect(localRow.getByText('Local', { exact: true })).toBeVisible()
    await expect(localRow.getByText('Dormant', { exact: true })).toBeVisible()
    await expect(row(adminPage, usernames[1]).getByText('LDAP', { exact: true })).toBeVisible()
    await expect(row(adminPage, usernames[2]).getByText('Unknown', { exact: true })).toBeVisible()
    await expect(row(adminPage, usernames[2]).getByRole('button', { name: 'Reset password' })).toHaveCount(0)
    const help = row(adminPage, usernames[1]).getByRole('button', { name: 'Password help' })
    await help.click()
    const directoryDialog = adminPage.getByRole('dialog', { name: 'Directory-managed password' })
    await expect(directoryDialog).toContainText('A directory administrator must reset it there')
    await expect(directoryDialog).toHaveJSProperty('open', true)
    expect(await directoryDialog.evaluate(element => element.matches(':modal'))).toBe(true)
    await expect(directoryDialog.getByRole('button', { name: 'Close', exact: true })).toBeFocused()
    // Native modality must prevent focus from reaching the background table.
    await adminPage.getByRole('button', { name: 'Create User', exact: true }).focus()
    await expect(directoryDialog.getByRole('button', { name: 'Close', exact: true })).toBeFocused()
    await adminPage.keyboard.press('Escape')
    await expect(directoryDialog).toHaveCount(0)
    await expect(help).toBeFocused()
    const reactivate = localRow.getByRole('button', { name: 'Reactivate', exact: true })
    await reactivate.click()
    const confirmation = adminPage.getByRole('dialog', { name: 'Reactivate account' })
    await expect(confirmation.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused()
    await adminPage.keyboard.press('Escape')
    await expect(reactivate).toBeFocused()
    await reactivate.click()
    await confirmation.getByRole('button', { name: 'Reactivate', exact: true }).click()
    await expect(localRow.getByText('Active', { exact: true })).toBeVisible()
    await expect(localRow.getByRole('button', { name: 'Reactivate', exact: true })).toHaveCount(0)

    // Enroll once, so the subsequent reset must preserve this exact factor.
    await signIn(viewerPage, usernames[0], initialTemporaryPassword)
    await expect(viewerPage).toHaveURL(/\/setup\/totp$/)
    await viewerPage.getByPlaceholder('New password', { exact: true }).fill(initialPassword)
    await viewerPage.getByPlaceholder('Confirm new password').fill(initialPassword)
    const secret = await viewerPage.locator('code').first().textContent() ?? ''
    if (!secret) throw new Error('Fixture MFA enrollment unavailable')
    const enrolledCode = authenticator.generate(secret)
    await viewerPage.locator('input[inputmode="numeric"]').first().fill(enrolledCode)
    await expect(viewerPage).toHaveURL(new RegExp(`^${baseURL}/?$`))

    // Enrollment replaces the initial password and may advance the credential
    // revision. Open recovery against the current authoritative row snapshot.
    await adminPage.reload()
    await expect(localRow.getByText('Enabled', { exact: true })).toBeVisible()
    const reset = localRow.getByRole('button', { name: 'Reset password', exact: true })
    await reset.click()
    const resetDialog = adminPage.getByRole('dialog', { name: 'Reset local password' })
    expect(await resetDialog.evaluate(element => element.matches(':modal'))).toBe(true)
    await expect(resetDialog.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused()
    await adminPage.keyboard.press('Tab')
    await expect(resetDialog.getByRole('button', { name: 'Generate temporary password', exact: true })).toBeFocused()
    await adminPage.keyboard.press('Shift+Tab')
    await expect(resetDialog.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused()
    await adminPage.keyboard.press('Escape')
    await expect(resetDialog).toHaveCount(0)
    await expect(reset).toBeFocused()
    await reset.click()
    const [resetResponse] = await Promise.all([
      adminPage.waitForResponse(response => response.url().endsWith(`/api/users/${createdIds[0]}/password-reset`) && response.request().method() === 'POST'),
      adminPage.getByRole('button', { name: 'Generate temporary password', exact: true }).click(),
    ])
    // Status/headers are safe assertion evidence; never include this response's
    // one-time credential body in diagnostics or attachments.
    expect(resetResponse.status()).toBe(200)
    expect(resetResponse.headers()['cache-control']).toContain('no-store')
    const dialog = adminPage.getByRole('dialog')
    await expect(dialog.getByRole('heading', { name: 'Temporary password generated' })).toBeVisible()
    await expect(dialog.getByRole('button', { name: 'Copy', exact: true })).toBeFocused()
    const temporaryPassword = await dialog.locator('code').textContent() ?? ''
    if (!temporaryPassword) throw new Error('Fixture temporary password unavailable')
    await expect(dialog.getByText(/Expires:/)).toBeVisible()
    await adminPage.keyboard.press('Escape')
    await expect(adminPage.getByRole('dialog')).toHaveCount(0)
    await expect(reset).toBeFocused()
    const revoked = await viewerPage.request.get(baseURL + '/api/servers')
    expect(revoked.status()).toBe(401)

    await signIn(viewerPage, usernames[0], temporaryPassword)
    await expect(viewerPage).toHaveURL(/\/login\/totp$/)
    const recoveryCode = await nextCode(viewerPage, secret, enrolledCode)
    await viewerPage.locator('input[inputmode="numeric"]').first().fill(recoveryCode)
    await expect(viewerPage.getByText('Change temporary password', { exact: true })).toBeVisible()
    await expect(viewerPage.getByRole('navigation')).toHaveCount(0)
    const noNormalAuthority = await viewerPage.request.get(baseURL + '/api/servers')
    expect(noNormalAuthority.status()).toBe(401)
    await viewerPage.getByLabel('New password', { exact: true }).fill(permanentPassword)
    await viewerPage.getByLabel('Confirm new password', { exact: true }).fill(permanentPassword)
    const [completionResponse] = await Promise.all([
      viewerPage.waitForResponse(response => response.url().endsWith('/api/auth/password/recovery') && response.request().method() === 'POST'),
      viewerPage.getByRole('button', { name: 'Change password and return to sign-in', exact: true }).click(),
    ])
    expect(completionResponse.status()).toBe(200)
    await expect(viewerPage).toHaveURL(/\/login$/)
    const stillNoSession = await viewerPage.request.get(baseURL + '/api/servers')
    expect(stillNoSession.status()).toBe(401)

    // Drain the shared three-verifications-per-minute limiter before proving
    // a fresh permanent-password login with the original enrolled factor.
    await viewerPage.waitForTimeout(62_000)
    await signIn(viewerPage, usernames[0], permanentPassword)
    await expect(viewerPage).toHaveURL(/\/login\/totp$/)
    const normalCode = await nextCode(viewerPage, secret, recoveryCode)
    await viewerPage.locator('input[inputmode="numeric"]').first().fill(normalCode)
    await expect(viewerPage).toHaveURL(new RegExp(`^${baseURL}/?$`))
    await expect(viewerPage.getByText('Fleet Dashboard', { exact: true }).first()).toBeVisible()
    await expect(viewerPage.getByText('Change temporary password', { exact: true })).toHaveCount(0)
  } finally {
    for (const id of createdIds) await adminPage.request.delete(`${baseURL}/api/users/${id}`, { headers: { 'X-CSRF-Token': csrf } })
    await viewerContext.close()
    await adminContext.close()
  }
})
