import { spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { expect, type Page } from '@playwright/test'
import { authenticator } from 'otplib'
import { hostCookieURL } from './helpers'

function docker(operation: string, args: string[]): string {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 30_000 })
  // Enrollment passes a one-time token to the agent. Keep command arguments
  // and subprocess output out of diagnostics.
  if (result.status !== 0) throw new Error(`Docker ${operation} failed (${result.status ?? result.signal ?? 'could not run Docker'})`)
  return result.stdout.trim()
}

async function enrollAdmin(baseURL: string): Promise<string> {
  const register = await fetch(baseURL + '/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', email: 'admin@example.test', password: `E2e!${randomUUID()}` }),
  })
  expect(register.status).toBe(200)
  const { setup_token: setupToken } = await register.json() as { setup_token: string }
  const headers = { Authorization: `Bearer ${setupToken}`, 'Content-Type': 'application/json' }
  const setup = await fetch(baseURL + '/api/auth/totp/setup', { method: 'POST', headers })
  expect(setup.status).toBe(200)
  const { secret } = await setup.json() as { secret: string }
  const enable = await fetch(baseURL + '/api/auth/totp/enable', {
    method: 'POST',
    headers,
    body: JSON.stringify({ code: authenticator.generate(secret) }),
  })
  expect(enable.status).toBe(200)
  const { access_token: accessToken } = await enable.json() as { access_token: string }
  return accessToken
}

export async function withEnrolledAgent(
  page: Page,
  fixture: { source: string; name: string },
  run: (serverURL: string) => Promise<void>,
) {
  const network = `veyport-file-e2e-${randomUUID()}`
  const hub = `${network}-hub`
  const agent = `${network}-agent`
  const image = process.env.E2E_IMAGE || 'veyport-e2e:test'
  const arch = docker('inspect image', ['image', 'inspect', '--format', '{{.Architecture}}', image])

  docker('create network', ['network', 'create', network])
  try {
    docker('start Hub', [
      'run', '--rm', '-d', '--name', hub, '--network', network,
      '-p', '127.0.0.1::8081', image,
      '--addr', ':8081', '--grpc-addr', ':9090', '--db', '/data/veyport.db', '--agent-bin-dir', '/app',
      '--grpc-external-addr', `${hub}:9090`,
    ])
    const published = docker('get Hub port', ['port', hub, '8081/tcp'])
    const port = /^127\.0\.0\.1:(\d+)$/.exec(published)?.[1]
    if (!port) throw new Error('Hub is missing its loopback HTTP port')
    const baseURL = `http://localhost:${port}`
    await expect.poll(async () => {
      const response = await fetch(baseURL + '/api/auth/status', { signal: AbortSignal.timeout(1000) }).catch(() => null)
      return response?.status
    }, { message: 'Hub is ready', timeout: 30_000 }).toBe(200)

    const accessToken = await enrollAdmin(baseURL)
    const headers = { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
    const created = await fetch(baseURL + '/api/servers', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: 'file-preview-e2e' }),
    })
    expect(created.status).toBe(201)
    const server = await created.json() as {
      server: { id: string }
      registration_token: string
      install_command: string
    }
    const caPin = /--ca-pin '([^']+)'/.exec(server.install_command)?.[1]
    if (!caPin) throw new Error('Agent enrollment command is missing its CA pin')

    docker('start agent', [
      'run', '--rm', '-d', '--name', agent, '--network', network,
      '--mount', `type=bind,source=${fixture.source},target=/${fixture.name},readonly`,
      '--entrypoint', `/app/veyport-agent-linux-${arch}`, image,
      '--hub', `${hub}:9090`, '--token', server.registration_token, '--ca-pin', caPin,
      '--config', '/tmp/veyport-agent.conf', '--cert-dir', '/tmp/veyport-tls', '--dropzone-dir', '/tmp/veyport-dropzone',
    ])
    await expect.poll(async () => {
      const response = await fetch(`${baseURL}/api/servers/${server.server.id}`, { headers, signal: AbortSignal.timeout(1000) })
      if (response.ok) return ((await response.json()) as { status: string }).status
      return response.status
    }, { message: 'Enrolled agent is online', timeout: 45_000 }).toBe('online')

    await page.context().addCookies([{
      name: '__Host-veyport_access', value: accessToken, url: hostCookieURL(baseURL),
      httpOnly: true, secure: true, sameSite: 'Strict',
    }])
    await run(`${baseURL}/servers/${server.server.id}`)
  } finally {
    // `--rm` removes anonymous volumes. The names are unique to this test.
    spawnSync('docker', ['rm', '-fv', agent, hub], { stdio: 'ignore', timeout: 30_000 })
    docker('remove network', ['network', 'rm', network])
  }
}
