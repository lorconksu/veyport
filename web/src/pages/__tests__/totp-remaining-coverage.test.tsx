import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { LoginTOTPPage } from '../login-totp'
import { SetupTOTPPage } from '../setup-totp'
import type { User } from '@/types/api'

// Canvas rendering is a browser boundary; the digit hook, auth and HTTP client run unchanged.
vi.mock('qrcode', () => ({ default: { toCanvas: vi.fn().mockResolvedValue(undefined) } }))
const fetchMock = vi.fn<typeof fetch>()
const user: User = { id: 'actor', username: 'signed-in', email: 'actor@example.test', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }
let router: ReturnType<typeof createMemoryRouter>
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }) }
function deferred() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>(yes => { resolve = yes })
  return { promise, resolve }
}
function Destination() {
  const { user } = useAuth()
  return <output>{user ? `Authenticated ${user.username}` : 'Unauthenticated'}</output>
}
const flows = [
  { name: 'login', path: '/login/totp', state: { totpToken: 'memory-login-token', returnTo: '/applications/app-1/launch?path=%2F' }, element: <LoginTOTPPage />, endpoint: '/api/auth/login/totp', button: 'Verify' },
  { name: 'setup', path: '/setup/totp', state: { setupToken: 'memory-setup-token', returnTo: '/applications/app-1/launch?path=%2F' }, element: <SetupTOTPPage />, endpoint: '/api/auth/totp/enable', button: 'Verify & Enable 2FA' },
] as const
async function renderFlow(flow: typeof flows[number], state: object | null = flow.state) {
  router = createMemoryRouter([
    { path: flow.path, element: flow.element },
    { path: '/applications/:id/launch', element: <Destination /> },
    { path: '/login', element: <p>Sign in again</p> },
  ], { initialEntries: [{ pathname: flow.path, state }] })
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>)
  await screen.findByRole('button', { name: flow.button })
}
function submissions(endpoint: string) { return fetchMock.mock.calls.filter(([url]) => url === endpoint) }
async function enterWithoutAutoSubmit() {
  const inputs = screen.getAllByRole('textbox')
  // A person can enter the boxes out of order. Completing the first box last
  // leaves the explicit Verify action available without triggering automatic submit.
  for (const index of [5, 4, 3, 2, 1, 0]) await userEvent.type(inputs[index], String(index + 1))
}
beforeEach(() => {
  vi.spyOn(document, 'cookie', 'get').mockReturnValue('__Host-veyport_csrf=totp-csrf')
  vi.stubGlobal('fetch', fetchMock.mockReset().mockImplementation(async input => {
    if (input === '/api/auth/me') return json({}, 401)
    if (input === '/api/auth/totp/setup') return json({ secret: 'SYNTHETICSETUP', qr_url: 'otpauth://totp/example?secret=SYNTHETICSETUP' })
    throw new Error(`Unexpected request: ${String(input)}`)
  }))
})
afterEach(() => { cleanup(); router?.dispose(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe.each(flows)('$name verification through the public digit inputs', flow => {
  it('allows an explicit click, blocks repeats while pending and installs authority only on success', async () => {
    const pending = deferred()
    const read = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation((input, options) => input === flow.endpoint ? pending.promise : read(input, options))
    await renderFlow(flow)
    expect(screen.getByRole('button', { name: flow.button })).toBeDisabled()
    await enterWithoutAutoSubmit()
    expect(submissions(flow.endpoint)).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: flow.button }))
    const verifying = screen.getByRole('button', { name: 'Verifying...' })
    expect(verifying).toBeDisabled()
    screen.getAllByRole('textbox').forEach(input => expect(input).toBeDisabled())
    await userEvent.click(verifying)
    expect(submissions(flow.endpoint)).toHaveLength(1)
    const [, options] = submissions(flow.endpoint)[0]
    expect(options?.method).toBe('POST')
    expect(options?.credentials).toBe('same-origin')
    expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('totp-csrf')
    expect(JSON.parse(String(options?.body))).toEqual(flow.name === 'login' ? { totp_token: 'memory-login-token', code: '123456' } : { code: '123456' })
    if (flow.name === 'setup') expect(new Headers(options?.headers).get('Authorization')).toBe('Bearer memory-setup-token')
    expect(router.state.location.pathname).toBe(flow.path)
    expect(router.state.location.search).toBe('')
    await act(async () => pending.resolve(json({ user })))
    expect(await screen.findByText('Authenticated signed-in')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/applications/app-1/launch')
    expect(submissions(flow.endpoint)).toHaveLength(1)
  })

  it('shows a refused click request, clears the code, then permits a single automatic retry', async () => {
    const read = fetchMock.getMockImplementation()!
    let attempts = 0
    fetchMock.mockImplementation((input, options) => input === flow.endpoint ? Promise.resolve(++attempts === 1 ? json({ error: 'Code expired' }, 403) : json({ user })) : read(input, options))
    await renderFlow(flow)
    await enterWithoutAutoSubmit()
    await userEvent.click(screen.getByRole('button', { name: flow.button }))
    expect(await screen.findByText('Code expired')).toBeInTheDocument()
    screen.getAllByRole('textbox').forEach(input => expect(input).toHaveValue(''))
    expect(screen.getByRole('button', { name: flow.button })).toBeDisabled()
    expect(router.state.location.pathname).toBe(flow.path)
    fireEvent.change(screen.getAllByRole('textbox')[0], { target: { value: '654321' } })
    expect(await screen.findByText('Authenticated signed-in')).toBeInTheDocument()
    expect(submissions(flow.endpoint)).toHaveLength(2)
    expect(JSON.parse(String(submissions(flow.endpoint)[1][1]?.body)).code).toBe('654321')
    await waitFor(() => expect(screen.queryByText('Code expired')).not.toBeInTheDocument())
  })

  it('requires the in-memory challenge token', async () => {
    router = createMemoryRouter([{ path: flow.path, element: flow.element }, { path: '/login', element: <p>Sign in again</p> }], { initialEntries: [flow.path] })
    render(<AuthProvider><RouterProvider router={router} /></AuthProvider>)
    expect(await screen.findByText('Sign in again')).toBeInTheDocument()
    expect(submissions(flow.endpoint)).toHaveLength(0)
    expect(fetchMock.mock.calls.filter(([url]) => url === '/api/auth/totp/setup')).toHaveLength(0)
  })
})
