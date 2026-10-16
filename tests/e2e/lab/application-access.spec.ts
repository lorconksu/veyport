import { createHash } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
import { closeMixedStreams, identities, mutateDirectory, nativeCredentials, nativeLogin, openApplication, openLiveStreams, openMixedStreams, portalAPI, portalPage, requireStreamRevocation, ROUTES, runtime, trustedContext } from './application-access-fixture'

test('real browser preserves native authentication and streams through direct and node HTTP/HTTPS', async () => {
  test.skip(!process.env.VEYPORT_APPLICATION_LAB_DIR, 'Explicit disposable application lab required')
  const fixture = runtime(), session = await trustedContext('viewer')
  let leaked = false
  session.context.on('request', async request => {
    if (new URL(request.url()).hostname.endsWith('.apps.yiucloud.com')) {
      const headers = await request.allHeaders()
      if (/__Host-veyport_(?:access|refresh|csrf)=/.test(headers.cookie ?? '')) leaked = true
    }
  })
  try {
    const portal = await portalPage(session.context)
    await expect(portal.locator('article')).toHaveCount(5)
    for (const slug of ROUTES) {
      const app = fixture.applications[slug], page = await openApplication(session.context, portal, app)
      expect(await page.evaluate(() => window.opener === null)).toBe(true)
      await nativeLogin(page)
      expect((await page.locator('body').textContent())?.includes('"authentication":"cookie"')).toBe(true)
      await page.goto(`https://${app.public_hostname}/form`)
      await page.getByRole('button', { name: 'Submit native form' }).click()
      expect((await page.locator('body').textContent())?.includes('"csrf":"accepted"')).toBe(true)
      await page.goto(`https://${app.public_hostname}/`)
      const basic = await page.evaluate(async credentials => {
        const response = await fetch('basic', { headers: { Authorization: `Basic ${btoa(`${credentials.username}:${credentials.password}`)}` } })
        return { status: response.status, authentication: (await response.json()).authentication }
      }, nativeCredentials())
      expect(basic).toEqual({ status: 200, authentication: 'basic' })
      const inspect = await page.evaluate(async () => (await fetch('inspect', { headers: { 'X-Veyport-User': 'synthetic', 'X-Veyport-Token': 'synthetic' } })).json()) as { cookies: string[]; headers: string[] }
      expect(inspect.cookies.some(name => /^(?:__Host-)?veyport_/.test(name))).toBe(false)
      expect(inspect.headers.some(name => /^x-veyport-/i.test(name))).toBe(false)
      const gateway = (await session.context.cookies(`https://${app.public_hostname}`)).filter(cookie => cookie.name.startsWith('__Host-veyport_'))
      expect(gateway.map(cookie => cookie.name)).toEqual(['__Host-veyport_app'])
      expect(gateway.every(cookie => cookie.domain === app.public_hostname && cookie.path === '/' && cookie.secure && cookie.httpOnly)).toBe(true)
      const socket = await page.evaluate(() => new Promise<boolean>(resolve => {
        let stage = 0
        const ws = new WebSocket(`${location.origin.replace('https:', 'wss:')}/ws`, 'veyport-fixture')
        ws.binaryType = 'arraybuffer'
        const timer = setTimeout(() => { ws.close(); resolve(false) }, 10_000)
        ws.onopen = () => ws.send('native websocket')
        ws.onmessage = event => {
          if (stage === 0) {
            if (event.data !== 'native websocket') { clearTimeout(timer); ws.close(); resolve(false); return }
            stage++; ws.send(new Uint8Array([0, 1, 255, 7]))
          } else {
            const bytes = new Uint8Array(event.data)
            clearTimeout(timer)
            const ok = ws.protocol === 'veyport-fixture' && bytes.length === 4 && bytes[2] === 255
            ws.close(); resolve(ok)
          }
        }
        ws.onerror = () => { clearTimeout(timer); resolve(false) }
      }))
      expect(socket).toBe(true)
      const events = await page.evaluate(() => new Promise<boolean>(resolve => {
        const stream = new EventSource('/sse'), timer = setTimeout(() => { stream.close(); resolve(false) }, 5_000)
        stream.onmessage = () => { clearTimeout(timer); stream.close(); resolve(true) }
        stream.onerror = () => { clearTimeout(timer); stream.close(); resolve(false) }
      }))
      expect(events).toBe(true)
      console.info(`[application-lab] native compatibility passed: ${slug}`)
      await page.close()
    }
    expect(leaked).toBe(false)
    const fresh = await trustedContext('viewer')
    try {
      const page = await fresh.context.newPage(), destination = `https://${fixture.applications['direct-http'].public_hostname}/form?direct=link`
      await page.goto(destination); await page.waitForURL(destination)
      await expect(page.getByRole('heading', { name: 'Native CSRF form' })).toBeVisible()
    } finally { await fresh.close() }
  } finally { await session.close() }
})

test('real sibling and opaque-origin forms are rejected before upstream mutation', async () => {
  test.skip(!process.env.VEYPORT_APPLICATION_LAB_DIR, 'Explicit disposable application lab required')
  const fixture = runtime(), session = await trustedContext('viewer')
  try {
    const portal = await portalPage(session.context)
    const first = await openApplication(session.context, portal, fixture.applications['direct-http'])
    const second = await openApplication(session.context, portal, fixture.applications['node-http'])
    const destination = `https://${fixture.applications['node-http'].public_hostname}/upload`
    const before = await second.evaluate(async () => (await fetch('/stats')).json()) as { requests: Record<string, number> }
    const refused = first.waitForResponse(response => response.url() === destination)
    await first.evaluate(async destination => {
      try { await fetch(destination, { method: 'POST', credentials: 'include', body: 'synthetic mutation', headers: { 'Content-Type': 'text/plain' } }) } catch { /* CORS also prevents reading the response. */ }
    }, destination)
    const response = await refused
    expect(response.status()).toBe(403)
    expect(response.request().headers().origin).toBe(new URL(first.url()).origin)
    const after = await second.evaluate(async () => (await fetch('/stats')).json()) as { requests: Record<string, number> }
    expect(after.requests['/upload'] ?? 0).toBe(before.requests['/upload'] ?? 0)
    const launch = `https://${fixture.applications['direct-http'].public_hostname}/_veyport/launch`
    const opaque = first.waitForResponse(response => response.url() === launch)
    await first.evaluate(launch => {
      const iframe = document.createElement('iframe')
      iframe.sandbox.add('allow-scripts', 'allow-forms')
      iframe.srcdoc = `<form method="post" action="${launch}"><input name="ticket" value="${'a'.repeat(43)}"></form><script>document.querySelector('form').submit()</script>`
      document.body.append(iframe)
    }, launch)
    const opaqueResponse = await opaque
    expect(opaqueResponse.request().headers().origin).toBe('null')
    expect(opaqueResponse.status()).toBe(403)
    console.info('[application-lab] sibling/null Origin refused without upstream mutation')
  } finally { await session.close() }
})

test('real browser uploads 64 MiB through the node HTTP app without corruption', async () => {
  test.skip(!process.env.VEYPORT_APPLICATION_LAB_DIR, 'Explicit disposable application lab required')
  const session = await trustedContext('viewer')
  try {
    const portal = await portalPage(session.context), page = await openApplication(session.context, portal, runtime().applications['node-http'])
    const block = Buffer.alloc(65_536)
    for (let index = 0; index < block.length; index++) block[index] = index % 256
    const expected = createHash('sha256')
    for (let index = 0; index < 1024; index++) expected.update(block)
    const result = await page.evaluate(async () => {
      const block = new Uint8Array(65_536)
      for (let index = 0; index < block.length; index++) block[index] = index % 256
      const response = await fetch('/upload', { method: 'POST', body: new Blob(Array.from({ length: 1024 }, () => block), { type: 'application/octet-stream' }) })
      const value = await response.json()
      return { status: response.status, bytes: value.bytes, sha256: value.sha256 }
    })
    expect(result).toEqual({ status: 200, bytes: 64 << 20, sha256: expected.digest('hex') })
    console.info('[application-lab] browser 64 MiB HTTP byte integrity passed')
  } finally { await session.close() }
})

test('actual WS and SSE close within five seconds after each local authority mutation', async () => {
  test.skip(process.env.VEYPORT_APPLICATION_LAB_MUTATIONS !== '1', 'Explicit synthetic mutation phase required; completed source sessions must be reseeded afterward')
  const fixture = runtime(), people = identities().users
  const sessions = await Promise.all((['admin', 'viewer', 'group', 'role'] as const).map(trustedContext))
  try {
    const [admin, viewer, group, role] = await Promise.all(sessions.map(session => portalPage(session.context)))
    const checked = async (method: string, url: string, data?: unknown) => {
      const result = await portalAPI(admin, method, url, data)
      expect([200, 204]).toContain(result.status)
      return result.body as Record<string, unknown>
    }
    const requireEnded = async (page: Page, start: number, label: string) => {
      const result = await requireStreamRevocation(page, start)
      expect(result.delay).toBeLessThanOrEqual(5_000)
      expect([401, 404]).toContain(result.status)
      console.info(`[application-lab] ${label}: WS/SSE closed after ${result.delay} ms`)
      await page.close()
    }
    const appPath = (slug: string) => `/api/admin/applications/${fixture.applications[slug].id}`
    let live = await openApplication(sessions[1].context, viewer, fixture.applications['direct-http'])
    await openLiveStreams(live)
    let current = await checked('GET', appPath('direct-http')), started = Date.now()
    try {
      await checked('PUT', `${appPath('direct-http')}/grants`, { grants: [], expected_version: current.config_version })
      await requireEnded(live, started, 'individual grant removal')
    } finally {
      current = await checked('GET', appPath('direct-http'))
      await checked('PUT', `${appPath('direct-http')}/grants`, { grants: [{ kind: 'user', subject_id: people.viewer.id }], expected_version: current.config_version })
    }
    live = await openApplication(sessions[1].context, viewer, fixture.applications['node-http'])
    await openLiveStreams(live); current = await checked('GET', appPath('node-http')); started = Date.now()
    try {
      await checked('PUT', appPath('node-http'), { ...current, enabled: false, expected_version: current.config_version })
      await requireEnded(live, started, 'application disable')
    } finally {
      current = await checked('GET', appPath('node-http'))
      await checked('PUT', appPath('node-http'), { ...current, enabled: true, expected_version: current.config_version })
    }
    live = await openApplication(sessions[2].context, group, fixture.applications['group-http'])
    await openLiveStreams(live)
    const groupPath = `/api/admin/application-groups/${fixture.group_id}`
    current = await checked('GET', groupPath); started = Date.now()
    try {
      await checked('PUT', groupPath, { name: current.name, user_ids: [], expected_version: current.version })
      await requireEnded(live, started, 'local group removal')
    } finally {
      current = await checked('GET', groupPath)
      await checked('PUT', groupPath, { name: current.name, user_ids: [people.group.id], expected_version: current.version })
    }
    live = await openApplication(sessions[3].context, role, fixture.applications['role-http'])
    await openLiveStreams(live); started = Date.now()
    try {
      await checked('PUT', `/api/users/${people.role.id}/role`, { role: 'auditor' })
      await requireEnded(live, started, 'Veyport role removal')
    } finally { await checked('PUT', `/api/users/${people.role.id}/role`, { role: 'viewer' }) }
    live = await openApplication(sessions[1].context, viewer, fixture.applications['node-https'])
    await openLiveStreams(live)
    const listed = await portalAPI(viewer, 'GET', '/api/auth/application-sessions')
    expect(listed.status).toBe(200)
    const active = (listed.body as { sessions: { id: string; application_id: string; ended_at?: string }[] }).sessions.find(item => item.application_id === fixture.applications['node-https'].id && !item.ended_at)
    if (!active) throw new Error('Current synthetic app session missing')
    started = Date.now()
    expect((await portalAPI(viewer, 'DELETE', `/api/auth/application-sessions/${active.id}`)).status).toBe(200)
    await requireEnded(live, started, 'own application-session revoke')
    live = await openApplication(sessions[1].context, viewer, fixture.applications['direct-https'])
    await openLiveStreams(live); started = Date.now()
    try {
      await checked('PUT', `/api/users/${people.viewer.id}/status`, { disabled: true })
      await requireEnded(live, started, 'user disable')
    } finally { await checked('PUT', `/api/users/${people.viewer.id}/status`, { disabled: false }) }
  } finally { await Promise.all(sessions.map(session => session.close())) }
})

test('twenty real application streams coexist with terminal output and progressing heartbeats', async () => {
  test.skip(process.env.VEYPORT_APPLICATION_LAB_STRESS !== '1', 'Explicit synthetic stress phase required; run separately from authority mutations')
  const fixture = runtime(), viewer = await trustedContext('viewer'), admin = await trustedContext('admin')
  const pages: Page[] = []
  let terminal: { page: Page; id: string } | undefined
  try {
    const portal = await portalPage(viewer.context), control = await portalPage(admin.context)
    for (const slug of ROUTES) {
      const page = await openApplication(viewer.context, portal, fixture.applications[slug])
      pages.push(page); await openMixedStreams(page)
    }
    const nodePath = `/api/servers/${fixture.node_id}`
    const before = await portalAPI(control, 'GET', nodePath)
    expect(before.status).toBe(200)
    const created = await portalAPI(control, 'POST', `${nodePath}/terminal/sessions`, { cols: 80, rows: 24, cwd: '/data' })
    expect(created.status).toBe(201)
    const id = (created.body as { session_id: string }).session_id
    terminal = { page: control, id }
    const streamPath = `${nodePath}/terminal/sessions/${id}/stream`
    const response = control.waitForResponse(response => new URL(response.url()).pathname === streamPath)
    await control.evaluate(streamPath => {
      const events = new EventSource(streamPath)
      window.__applicationTerminal = { text: '', events }
      events.onmessage = event => { window.__applicationTerminal.text += atob(event.data) }
    }, streamPath)
    expect((await response).status()).toBe(200)
    expect((await portalAPI(control, 'POST', `${nodePath}/terminal/sessions/${id}/input`, { data: 'printf "APPLICATION_QA_CONTROL_ALIVE\\n"\n' })).status).toBe(202)
    await control.waitForFunction(() => window.__applicationTerminal.text.includes('APPLICATION_QA_CONTROL_ALIVE'))
    for (let index = 0; index < 13; index++) {
      await new Promise(resolve => setTimeout(resolve, 5_000))
      for (const page of pages) {
        const alive = await page.evaluate(() => ({ open: window.__applicationMixed.open, closed: window.__applicationMixed.closed, echoes: window.__applicationMixed.echoes, messages: window.__applicationMixed.messages }))
        expect(alive.open).toBe(5); expect(alive.closed).toBe(0)
        expect(alive.echoes).toBeGreaterThan(0); expect(alive.messages).toBeGreaterThan(0)
      }
    }
    const after = await portalAPI(control, 'GET', nodePath)
    expect(after.status).toBe(200)
    expect((after.body as { status: string }).status).toBe('online')
    expect((after.body as { last_seen_at: string }).last_seen_at).not.toBe((before.body as { last_seen_at: string }).last_seen_at)
    console.info('[application-lab] twenty app streams, real terminal and heartbeat progression passed')
  } finally {
    for (const page of pages) if (!page.isClosed()) await closeMixedStreams(page)
    if (terminal) await portalAPI(terminal.page, 'DELETE', `/api/servers/${fixture.node_id}/terminal/sessions/${terminal.id}`)
    await Promise.all([viewer.close(), admin.close()])
  }
})

test('real TLS name/CA and protected control targets refuse upstream HTTP traffic', async () => {
  test.skip(process.env.VEYPORT_APPLICATION_LAB_NEGATIVES !== '1', 'Explicit preseeded negative-backend phase required')
  const fixture = runtime(), session = await trustedContext('denied'), observer = await trustedContext('viewer')
  try {
    const portal = await portalPage(session.context), allowed = await portalPage(observer.context)
    const observed = await openApplication(observer.context, allowed, fixture.applications['direct-http'])
    const before = await observed.evaluate(async () => (await fetch('/stats')).json()) as { requests: Record<string, number> }
    expect((await portalAPI(portal, 'POST', `/api/applications/${fixture.applications['direct-http'].id}/launch`, {})).status).toBe(403)
    for (const slug of ['wrong-ca-direct', 'wrong-name-direct', 'wrong-ca-node', 'wrong-name-node', 'control-direct', 'control-node']) {
      if (!fixture.applications[slug]) throw new Error('Controlled negative backend fixture missing')
      const page = await openApplication(session.context, portal, fixture.applications[slug])
      expect(await page.evaluate(async () => (await fetch('/health', { redirect: 'manual' })).status)).toBe(502)
      console.info(`[application-lab] configured backend refusal passed: ${slug}`)
      await page.close()
    }
    const after = await observed.evaluate(async () => (await fetch('/stats')).json()) as { requests: Record<string, number> }
    expect(after.requests['/health'] ?? 0).toBe(before.requests['/health'] ?? 0)
  } finally { await Promise.all([session.close(), observer.close()]) }
})

test('real clock separates dashboard idle, accepted app activity, logout and original MFA horizon', async () => {
  test.skip(process.env.VEYPORT_APPLICATION_LAB_TIMERS !== '1', 'Explicit timer phase with an older synthetic group MFA source required')
  const fixture = runtime(), sessions = await Promise.all((['admin', 'viewer', 'group'] as const).map(trustedContext))
  let settings: { idle_seconds: number; max_seconds: number } | undefined, hub: { session_idle_minutes: number } | undefined, control: Page | undefined
  try {
    const [admin, viewer, group] = await Promise.all(sessions.map(session => portalPage(session.context)))
    control = admin
    const checked = async (method: string, path: string, data?: unknown) => {
      const response = await portalAPI(admin, method, path, data)
      expect(response.status).toBe(200)
      return response.body as Record<string, unknown>
    }
    settings = await checked('GET', '/api/admin/application-settings') as unknown as typeof settings
    hub = await checked('GET', '/api/settings/hub') as unknown as typeof hub
    const source = await portalAPI(group, 'GET', '/api/auth/sessions')
    expect(source.status).toBe(200)
    const old = (source.body as { sessions: { current: boolean; created_at: string }[] }).sessions.find(item => item.current)
    if (!old || Date.now() - Date.parse(old.created_at) <= 300_000) throw new Error('Synthetic older source MFA required')
    const active = await openApplication(sessions[1].context, viewer, fixture.applications['direct-http'])
    const idle = await openApplication(sessions[1].context, viewer, fixture.applications['node-http'])
    const older = await openApplication(sessions[2].context, group, fixture.applications['group-http'])
    for (const page of [active, idle, older]) {
      await openLiveStreams(page)
      await page.evaluate(() => window.setInterval(() => { if (window.__applicationLive.ws.readyState === WebSocket.OPEN) window.__applicationLive.ws.send('native fixture keepalive') }, 10_000))
    }
    for (const page of [active, older]) await page.evaluate(() => window.setInterval(() => { void fetch('/health') }, 10_000))
    // Keep the exact portal origin and credentials, with no SPA polling.
    await viewer.goto('https://veyport.yiucloud.com/api/auth/status')
    await group.goto('https://veyport.yiucloud.com/api/auth/status')
    const policy = await checked('GET', '/api/admin/application-settings')
    await checked('PUT', '/api/admin/application-settings', { idle_seconds: 60, max_seconds: 43_200, expected_version: policy.version })
    await checked('PUT', '/api/settings/hub', { session_idle_minutes: 1 })
    for (let index = 0; index < 14; index++) {
      await new Promise(resolve => setTimeout(resolve, 5_000))
      expect((await portalAPI(admin, 'GET', '/api/auth/me')).status).toBe(200)
    }
    expect((await portalAPI(viewer, 'GET', '/api/auth/me')).status).toBe(401)
    expect(await active.evaluate(async () => (await fetch('/health', { redirect: 'manual' })).status)).toBe(200)
    expect(await active.evaluate(() => !window.__applicationLive.wsClosed && !window.__applicationLive.eventsClosed)).toBe(true)
    expect(await idle.evaluate(() => !!window.__applicationLive.wsClosed && !!window.__applicationLive.eventsClosed)).toBe(true)
    expect(await idle.evaluate(async () => (await fetch('/health', { redirect: 'manual' })).status)).toBe(401)
    const refused = await viewer.evaluate(async () => (await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': 'deliberately-invalid-synthetic-proof' } })).status)
    expect(refused).toBe(403)
    expect(await active.evaluate(() => !window.__applicationLive.wsClosed && !window.__applicationLive.eventsClosed)).toBe(true)
    let started = Date.now()
    expect((await portalAPI(viewer, 'POST', '/api/auth/logout', {})).status).toBe(204)
    expect((await requireStreamRevocation(active, started)).delay).toBeLessThanOrEqual(5_000)
    const current = await checked('GET', '/api/admin/application-settings')
    started = Date.now()
    await checked('PUT', '/api/admin/application-settings', { idle_seconds: 60, max_seconds: 300, expected_version: current.version })
    expect((await requireStreamRevocation(older, started)).delay).toBeLessThanOrEqual(5_000)
    console.info('[application-lab] independent request idle, failed/successful logout and original MFA maximum passed')
  } finally {
    if (control && settings) {
      const current = await portalAPI(control, 'GET', '/api/admin/application-settings')
      expect((await portalAPI(control, 'PUT', '/api/admin/application-settings', { ...settings, expected_version: (current.body as { version: number }).version })).status).toBe(200)
    }
    if (control && hub) expect((await portalAPI(control, 'PUT', '/api/settings/hub', { session_idle_minutes: hub.session_idle_minutes })).status).toBe(200)
    await Promise.all(sessions.map(session => session.close()))
  }
})


test('directory membership loss durably ends the app session and the old cookie cannot resume', async () => {
  test.skip(process.env.VEYPORT_APPLICATION_LAB_DIRECTORY !== '1', 'Explicit isolated TLS LDAP phase required')
  const fixture = runtime(), session = await trustedContext('qa-directorygroup')
  let removed = false
  try {
    const portal = await portalPage(session.context)
    const previous = await portalAPI(portal, 'GET', '/api/auth/application-sessions')
    expect(previous.status).toBe(200)
    const oldIDs = new Set((previous.body as { sessions: { id: string }[] }).sessions.map(item => item.id))
    const page = await openApplication(session.context, portal, fixture.applications['directory-group'])
    await openLiveStreams(page)
    const issued = await portalAPI(portal, 'GET', '/api/auth/application-sessions')
    expect(issued.status).toBe(200)
    const active = (issued.body as { sessions: { id: string; application_id: string }[] }).sessions.find(item => !oldIDs.has(item.id) && item.application_id === fixture.applications['directory-group'].id)
    if (!active) throw new Error('Exact newly issued directory app session missing')
    const started = Date.now()
    mutateDirectory('remove-group', 'qa-directorygroup'); removed = true
    const ended = await requireStreamRevocation(page, started)
    expect(ended.delay).toBeLessThanOrEqual(5_000)
    expect(ended.status).toBe(401)
    const history = await portalAPI(portal, 'GET', '/api/auth/application-sessions')
    expect(history.status).toBe(200)
    const row = (history.body as { sessions: { id: string; ended_at?: string }[] }).sessions.find(item => item.id === active.id)
    expect(!!row?.ended_at).toBe(true)
    mutateDirectory('restore-group', 'qa-directorygroup'); removed = false
    await new Promise(resolve => setTimeout(resolve, 3_000))
    expect(await page.evaluate(async () => (await fetch('/health', { redirect: 'manual' })).status)).toBe(401)
    console.info('[application-lab] directory grant loss persisted and restored membership cannot revive old cookie')
  } finally {
    if (removed) mutateDirectory('restore-group', 'qa-directorygroup')
    await session.close()
  }
})
