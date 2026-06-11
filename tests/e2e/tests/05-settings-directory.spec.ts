import { test, expect } from '@playwright/test'
import { loginViaAPI } from './helpers'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:18081'

// UI-level coverage for the Directory settings tab (specs/001 tasks T016/T020).
// Directory-backed flows (real sign-in) are covered by the Go integration
// suite; these tests intentionally avoid persisting any LDAP configuration so
// later specs see an unchanged hub.
test.describe('Settings - Directory tab', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page, BASE_URL)
    await page.goto(BASE_URL + '/settings?tab=directory')
    await expect(page).toHaveURL(/\/settings\?tab=directory/, { timeout: 10000 })
  })

  test('renders LDAP configuration form for admin', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Directory' })).toBeVisible()
    await expect(page.getByText('LDAP Directory')).toBeVisible()

    await expect(page.getByLabel('Enable LDAP')).toBeVisible()
    await expect(page.getByLabel('LDAP URL')).toBeVisible()
    await expect(page.getByLabel('Bind DN')).toBeVisible()
    await expect(page.getByLabel('Bind Password')).toBeVisible()
    await expect(page.getByLabel('User Base DN')).toBeVisible()
    await expect(page.getByLabel('Group Base DN')).toBeVisible()
    await expect(page.getByLabel('Admin Groups')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Save LDAP Settings' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Test Connection' })).toBeVisible()
  })

  test('save with missing required field shows named validation error', async ({ page }) => {
    // Enable LDAP and provide a URL, but leave User Base DN empty.
    await page.getByLabel('Enable LDAP').check()
    await page.getByLabel('LDAP URL').fill('ldaps://dir.example.com:636')

    await page.getByRole('button', { name: 'Save LDAP Settings' }).click()

    // Server-side validation names the missing field.
    await expect(page.getByText('LDAP user base DN is required when LDAP is enabled')).toBeVisible({
      timeout: 10000,
    })

    // Nothing was persisted: a reload shows LDAP still disabled.
    await page.reload()
    await expect(page).toHaveURL(/\/settings\?tab=directory/, { timeout: 10000 })
    await expect(page.getByLabel('Enable LDAP')).not.toBeChecked()
  })

  test('test connection against unreachable host shows failure without saving', async ({ page }) => {
    await page.getByLabel('Enable LDAP').check()
    // Closed port on the hub's own loopback: instant connection-refused,
    // unlike blackholed addresses which hang on the 60s dial timeout.
    await page.getByLabel('LDAP URL').fill('ldaps://127.0.0.1:1')
    await page.getByLabel('User Base DN').fill('ou=people,dc=example,dc=com')
    await page.getByLabel('Group Base DN').fill('ou=groups,dc=example,dc=com')
    await page.getByLabel('Admin Groups').fill('veyport-admins')

    await page.getByRole('button', { name: 'Test Connection' }).click()

    // The probe has a server-side timeout; failure feedback names the cause.
    await expect(page.getByText(/failed to connect to LDAP/)).toBeVisible({ timeout: 30000 })

    // The probe persisted nothing: a reload shows LDAP still disabled.
    await page.reload()
    await expect(page).toHaveURL(/\/settings\?tab=directory/, { timeout: 10000 })
    await expect(page.getByLabel('Enable LDAP')).not.toBeChecked()
  })
})
