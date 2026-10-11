import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { firefox, type BrowserContext, type Locator, type Page } from '@playwright/test'

export const HUB = 'https://10.10.1.59:8443'
const PRIVATE = path.join(os.homedir(), '.local/share/veyport-audit-lab/secrets')
const TOOLING = path.resolve(__dirname, '../../../infra/audit-lab/execution')
export type Person = 'officer' | 'approver-a' | 'approver-b'
export interface LabFixture {
  users: Record<Person, { id: string; username: string; password: string }>
  candidate_policy: { nodes: string[]; runtime_seconds: number; retention_hours: number; destination: string; credential_ref: string; trust_key_ids: string[]; qualification_sha256: string }
  target_id: string
}
export function privateFixture(): LabFixture {
  const descriptor = fs.openSync(path.join(PRIVATE, 'execution-fixture.json'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
  try {
    const info = fs.fstatSync(descriptor)
    if (!info.isFile() || info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o600 || info.size > 1 << 20) throw new Error('Private lab fixture rejected')
    return JSON.parse(fs.readFileSync(descriptor, 'utf8')) as LabFixture
  } finally { fs.closeSync(descriptor) }
}
export function freshCode(person: Person): string {
  const result = spawnSync('python3', ['-c', 'import json,sys; from qualify import fresh_code,private_bytes,STATE_FILE; s=json.loads(private_bytes(STATE_FILE)); print(fresh_code(s,sys.argv[1]))', person], { cwd: TOOLING, encoding: 'utf8', timeout: 70_000 })
  if (result.status !== 0 || !/^\d{6}\n?$/.test(result.stdout)) throw new Error('Fresh synthetic MFA preparation failed; private output withheld')
  return result.stdout.trim()
}
export async function privateFill(locator: Locator, value: string): Promise<void> {
  try { await locator.fill(value) } catch { throw new Error('Private browser input failed; input and call details withheld') }
}
export async function trustedContext(): Promise<{ context: BrowserContext; close: () => Promise<void> }> {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'veyport-browser-trust-'))
  fs.chmodSync(profile, 0o700)
  for (const args of [['-N', '-d', `sql:${profile}`, '--empty-password'], ['-A', '-d', `sql:${profile}`, '-n', 'isolated-veyport-lab', '-t', 'C,,', '-i', path.join(PRIVATE, 'ca.crt')]]) {
    const result = spawnSync('certutil', args, { stdio: 'pipe' })
    if (result.status) { fs.rmSync(profile, { recursive: true, force: true }); throw new Error('Isolated browser CA trust setup failed') }
  }
  let context: BrowserContext
  try { context = await firefox.launchPersistentContext(profile, { headless: true, ignoreHTTPSErrors: false, acceptDownloads: true }) }
  catch { fs.rmSync(profile, { recursive: true, force: true }); throw new Error('Trusted isolated Firefox launch failed') }
  context.setDefaultTimeout(20_000)
  context.setDefaultNavigationTimeout(30_000)
  return { context, close: async () => { try { await context.close() } finally { fs.rmSync(profile, { recursive: true, force: true }) } } }
}
export async function login(page: Page, person: Person): Promise<void> {
  const user = privateFixture().users[person]
  await page.goto(`${HUB}/login`)
  await privateFill(page.getByPlaceholder('username'), user.username)
  await privateFill(page.getByPlaceholder('password'), user.password)
  await page.getByRole('button', { name: 'Sign In', exact: true }).click()
  await page.waitForURL('**/login/totp')
  await privateFill(page.locator('input[inputmode="numeric"]').first(), freshCode(person))
  await page.waitForURL(`${HUB}/`)
}
export async function confirmFresh(page: Page, person: Person): Promise<void> {
  let status: number | undefined
  const recordStatus = (response: import('@playwright/test').Response) => {
    const pathname = new URL(response.url()).pathname
    if (pathname === '/api/security/step-up' || /^\/api\/security\/changes\/[a-zA-Z0-9_-]+\/(?:approve|apply)$/.test(pathname)) status = response.status()
  }
  page.on('response', recordStatus)
  try {
    await privateFill(page.getByLabel('Fresh MFA code'), freshCode(person))
    await page.getByRole('button', { name: 'Confirm with fresh MFA' }).click()
    await page.waitForFunction(() => {
      const dialog = document.querySelector('[role="dialog"]')
      return !dialog || !!dialog.querySelector('[role="alert"]')
    }, undefined, { timeout: 35_000 })
    if (await page.getByRole('dialog').getByRole('alert').count()) throw new Error('Refused')
  } catch {
    // Do not include request bodies, proof values, private inputs or call logs.
    throw new Error(`Fresh MFA operation did not complete; last protected HTTP status=${status ?? 'unavailable'}`)
  } finally { page.off('response', recordStatus) }
}
export async function safeStatus(page: Page, pathname: string): Promise<number> {
  if (!/^\/api\/[a-zA-Z0-9_/?=&.-]+$/.test(pathname)) throw new Error('Safe lab status route required')
  return page.evaluate(async pathname => (await fetch(pathname, { cache: 'no-store' })).status, pathname)
}
