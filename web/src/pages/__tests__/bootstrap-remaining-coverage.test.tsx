import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Root } from 'react-dom/client'
import { afterEach, expect, it, vi } from 'vitest'
import { queryClient } from '@/lib/query-client'

const lifecycle = vi.hoisted(() => ({ root: null as Root | null }))
// Retain the real root only for cleanup. Both createRoot and its render method
// run unchanged, mounting the actual StrictMode/App/provider/router tree.
vi.mock('react-dom/client', async importOriginal => {
  const actual = await importOriginal<typeof import('react-dom/client')>()
  return {
    ...actual,
    createRoot: (...args: Parameters<typeof actual.createRoot>) => {
      const root = actual.createRoot(...args)
      lifecycle.root = root
      return root
    },
  }
})

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}
let mount: HTMLDivElement
const originalUrl = window.location.href

afterEach(async () => {
  await act(async () => lifecycle.root?.unmount())
  lifecycle.root = null
  queryClient.clear()
  mount?.remove()
  window.history.replaceState(null, '', originalUrl)
  vi.unstubAllGlobals()
})

it('boots the real app into a protected route, requires sign-in and advances a retried login to MFA', async () => {
  mount = document.createElement('div')
  mount.id = 'root'
  document.body.append(mount)
  window.history.replaceState(null, '', '/applications/app-1/launch?path=%2Freports')
  let finishSessionCheck!: () => void
  const sessionCheck = new Promise<void>(resolve => { finishSessionCheck = resolve })
  let loginAttempts = 0
  const fetchMock = vi.fn<typeof fetch>(async (input, options = {}) => {
    if (input === '/api/auth/me') {
      await sessionCheck
      return json({ error: 'No session' }, 401)
    }
    if (input === '/api/auth/status') return json({ initialized: true })
    if (input === '/api/auth/login' && options.method === 'POST') {
      loginAttempts++
      return loginAttempts === 1
        ? json({ error: 'Invalid credentials' }, 401)
        : json({ totp_token: 'memory-only-bootstrap-challenge' })
    }
    throw new Error(`Unexpected request: ${String(input)}`)
  })
  vi.stubGlobal('fetch', fetchMock)

  await act(async () => { await import('@/main') })
  expect(lifecycle.root).not.toBeNull()
  expect(within(mount).getByText('Loading...')).toBeInTheDocument()
  expect(within(mount).queryByRole('button', { name: 'Sign In' })).not.toBeInTheDocument()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/auth/me').length).toBeGreaterThan(0)

  await act(async () => finishSessionCheck())
  const signIn = await within(mount).findByRole('button', { name: 'Sign In' })
  expect(window.location.pathname).toBe('/login')
  expect(within(mount).queryByText('Loading...')).not.toBeInTheDocument()
  await userEvent.type(screen.getByPlaceholderText('username'), 'operator')
  await userEvent.type(screen.getByPlaceholderText('password'), 'Synthetic#Bootstrap2026')
  await userEvent.click(signIn)
  expect(await within(mount).findByText('Invalid credentials')).toBeInTheDocument()
  expect(window.location.pathname).toBe('/login')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/auth/refresh')).toHaveLength(0)

  await userEvent.click(within(mount).getByRole('button', { name: 'Sign In' }))
  expect(await within(mount).findByText('Two-Factor Authentication')).toBeInTheDocument()
  expect(within(mount).getAllByRole('textbox')).toHaveLength(6)
  expect(within(mount).getByRole('button', { name: 'Verify' })).toBeDisabled()
  await waitFor(() => expect(window.location.pathname).toBe('/login/totp'))
  expect(window.location.search).toBe('')
  expect(window.location.href).not.toContain('memory-only-bootstrap-challenge')
  expect(mount.textContent).not.toContain('memory-only-bootstrap-challenge')
  const requests = fetchMock.mock.calls.filter(([url]) => url === '/api/auth/login')
  expect(requests).toHaveLength(2)
  for (const [, options] of requests) {
    expect(options?.credentials).toBe('same-origin')
    expect(JSON.parse(String(options?.body))).toEqual({ username: 'operator', password: 'Synthetic#Bootstrap2026' })
  }
})
