import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { firefox, type BrowserContext, type Locator, type Page } from '@playwright/test'

export type Person = 'admin' | 'viewer' | 'role' | 'group' | 'denied' | 'qa-directorygroup' | 'qa-directoryrole' | 'qa-directoryidentity'
export interface Application {
  id: string
  name: string
  public_hostname: string
  config_version: number
}
interface Runtime {
  node_id: string
  group_id: string
  applications: Record<string, Application>
  build: { source_manifest_sha256: string; image_id: string }
}
interface Identities {
  users: Record<Person, { id: string; username: string; password: string; totp_secret: string }>
}
export const PORTAL = 'https://veyport.yiucloud.com'
export const ROUTES = ['direct-http', 'direct-https', 'node-http', 'node-https'] as const

export function labDirectory(): string {
  const directory = process.env.VEYPORT_APPLICATION_LAB_DIR
  if (!directory || !path.isAbsolute(directory)) throw new Error('Explicit private application lab directory required')
  const info = fs.lstatSync(directory)
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o700) throw new Error('Owner-only private lab directory required')
  return directory
}
function privateFile(name: string): Buffer {
  const descriptor = fs.openSync(path.join(labDirectory(), name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
  try {
    const info = fs.fstatSync(descriptor)
    if (!info.isFile() || info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o600 || info.size > 4 << 20) throw new Error('Private application fixture file refused')
    return fs.readFileSync(descriptor)
  } finally { fs.closeSync(descriptor) }
}
export function runtime(): Runtime { return JSON.parse(privateFile('runtime.json').toString()) as Runtime }
export function identities(): Identities { return JSON.parse(privateFile('identities.json').toString()) as Identities }
export function nativeCredentials(): { username: string; password: string } {
  // The disposable runtime owns this copy; no real owner credentials are used.
  return JSON.parse(privateFile('direct-private/native-credentials.json').toString()) as { username: string; password: string }
}
export async function privateFill(locator: Locator, value: string): Promise<void> {
  try { await locator.fill(value) } catch { throw new Error('Private form input failed; value and call details withheld') }
}
export async function trustedContext(person: Person): Promise<{ context: BrowserContext; close(): Promise<void> }> {
  const root = labDirectory()
  privateFile('qa-ca.crt')
  const profile = fs.mkdtempSync(path.join(root, `regression-${person}-`))
  fs.chmodSync(profile, 0o700)
  for (const args of [['-N', '-d', `sql:${profile}`, '--empty-password'], ['-A', '-d', `sql:${profile}`, '-n', 'application-lab', '-t', 'C,,', '-i', path.join(root, 'qa-ca.crt')]]) {
    const result = spawnSync('certutil', args, { stdio: 'pipe' })
    if (result.status !== 0) { fs.rmSync(profile, { recursive: true, force: true }); throw new Error('Private browser CA trust setup failed') }
  }
  let context: BrowserContext | undefined
  try {
    // This localhost CONNECT service accepts only QA hosts and never resolves
    // them to the real staging service. Certificate verification stays enabled.
    context = await firefox.launchPersistentContext(profile, { headless: true, proxy: { server: 'http://127.0.0.1:19080' }, ignoreHTTPSErrors: false })
    const state = JSON.parse(privateFile(`${person}-browser-state.json`).toString()) as { cookies: Parameters<BrowserContext['addCookies']>[0] }
    await context.addCookies(state.cookies)
  } catch {
    try { await context?.close() } catch { /* Preserve the scrubbed setup error. */ }
    fs.rmSync(profile, { recursive: true, force: true })
    throw new Error('Trusted disposable browser setup failed; private details withheld')
  }
  const ready = context
  ready.setDefaultTimeout(15_000)
  return { context: ready, close: async () => { try { await ready.close() } finally { fs.rmSync(profile, { recursive: true, force: true }) } } }
}
export async function portalPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(`${PORTAL}/applications`)
  await page.getByRole('heading', { name: 'Applications', exact: true }).waitFor()
  return page
}
export async function openApplication(context: BrowserContext, portal: Page, app: Application): Promise<Page> {
  const article = portal.locator('article').filter({ has: portal.getByText(app.name, { exact: true }) })
  const opened = context.waitForEvent('page')
  await article.getByRole('link', { name: 'Open application' }).click()
  const page = await opened
  await page.waitForURL(`https://${app.public_hostname}/`, { timeout: 30_000 })
  return page
}
export async function portalAPI(page: Page, method: string, pathname: string, data?: unknown): Promise<{ status: number; body: unknown }> {
  if (new URL(page.url()).origin !== PORTAL || !/^\/api\/[a-zA-Z0-9_/?=&.-]+$/.test(pathname)) throw new Error('Fixed portal API boundary required')
  return page.evaluate(async ({ method, pathname, data }) => {
    const csrf = document.cookie.split('; ').find(value => value.startsWith('__Host-veyport_csrf='))?.split('=').slice(1).join('=')
    const response = await fetch(pathname, { method, headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) })
    let body: unknown = null
    try { body = await response.json() } catch { /* A successful DELETE has no body. */ }
    return { status: response.status, body }
  }, { method, pathname, data })
}
export async function nativeLogin(page: Page): Promise<void> {
  const origin = new URL(page.url()).origin
  const native = nativeCredentials()
  await page.goto(`${origin}/login`)
  await page.getByRole('heading', { name: 'Native application login' }).waitFor()
  await privateFill(page.getByLabel('Username'), native.username)
  await privateFill(page.getByLabel('Password'), native.password)
  await page.getByRole('button', { name: 'Submit native form' }).click()
  await page.waitForURL(`${origin}/whoami`)
}

declare global {
  interface Window {
    __applicationLive: { ws: WebSocket; events: EventSource; wsReady: boolean; eventsReady: boolean; wsClosed: number; eventsClosed: number }
  }
}
export async function openLiveStreams(page: Page): Promise<void> {
  await page.evaluate(() => {
    const ws = new WebSocket(`${location.origin.replace('https:', 'wss:')}/ws`, 'veyport-fixture'), events = new EventSource('/sse')
    const live: Window['__applicationLive'] = { ws, events, wsReady: false, eventsReady: false, wsClosed: 0, eventsClosed: 0 }
    window.__applicationLive = live
    ws.onopen = () => ws.send('synthetic access-removal test')
    ws.onmessage = () => { live.wsReady = true }
    ws.onclose = () => { live.wsClosed = Date.now() }
    events.onmessage = () => { live.eventsReady = true }
    events.onerror = () => { live.eventsClosed = Date.now(); events.close() }
  })
  await page.waitForFunction(() => window.__applicationLive.wsReady && window.__applicationLive.eventsReady)
}
export async function requireStreamRevocation(page: Page, started: number): Promise<{ delay: number; status: number }> {
  await page.waitForFunction(() => window.__applicationLive.wsClosed && window.__applicationLive.eventsClosed, undefined, { timeout: 5_500 })
  return page.evaluate(async started => ({ delay: Math.max(window.__applicationLive.wsClosed, window.__applicationLive.eventsClosed) - started, status: (await fetch('/health', { redirect: 'manual' })).status }), started)
}

declare global {
  interface Window {
    __applicationMixed: { open: number; closed: number; echoes: number; messages: number; sockets: WebSocket[]; events: EventSource[]; interval: number }
    __applicationTerminal: { text: string; events: EventSource }
  }
}
export async function openMixedStreams(page: Page): Promise<void> {
  await page.evaluate(() => {
    const mixed: Window['__applicationMixed'] = { open: 0, closed: 0, echoes: 0, messages: 0, sockets: [], events: [], interval: 0 }
    window.__applicationMixed = mixed
    for (let index = 0; index < 2; index++) {
      const ws = new WebSocket(`${location.origin.replace('https:', 'wss:')}/ws`, 'veyport-fixture')
      ws.onopen = () => { mixed.open++; ws.send('synthetic mixed traffic') }
      ws.onmessage = () => { mixed.echoes++ }
      ws.onclose = () => { mixed.closed++ }
      mixed.sockets.push(ws)
    }
    for (let index = 0; index < 3; index++) {
      const events = new EventSource('/sse')
      let opened = false
      events.onmessage = () => { mixed.messages++; if (!opened) { opened = true; mixed.open++ } }
      events.onerror = () => { mixed.closed++; events.close() }
      mixed.events.push(events)
    }
    mixed.interval = window.setInterval(() => mixed.sockets.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send('synthetic keepalive') }), 1_000)
  })
  await page.waitForFunction(() => window.__applicationMixed.open === 5)
}
export async function closeMixedStreams(page: Page): Promise<void> {
  await page.evaluate(() => {
    clearInterval(window.__applicationMixed.interval)
    window.__applicationMixed.sockets.forEach(ws => ws.close())
    window.__applicationMixed.events.forEach(events => events.close())
  })
}

export function mutateDirectory(action: 'remove-group' | 'restore-group', person: 'qa-directorygroup'): void {
  const script = path.join(labDirectory(), 'ldap-private', 'fixture.py')
  const descriptor = fs.openSync(script, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
  try {
    const info = fs.fstatSync(descriptor)
    if (!info.isFile() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0 || info.size > 1 << 20) throw new Error('Owner-only synthetic directory fixture required')
  } finally { fs.closeSync(descriptor) }
  const result = spawnSync('python3', [script, action, person], { stdio: 'pipe', timeout: 10_000 })
  if (result.status !== 0) throw new Error('Synthetic directory mutation failed; private details withheld')
}
