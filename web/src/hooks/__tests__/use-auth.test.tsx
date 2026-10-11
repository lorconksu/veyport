import { render, screen, waitFor, act } from '@testing-library/react'
import { vi } from 'vitest'
import { AuthProvider, useAuth } from '../use-auth'

// Mock auth
vi.mock('@/lib/auth', () => ({
  clearTokens: vi.fn().mockResolvedValue(undefined),
  getCSRFToken: vi.fn(() => ''),
}))

import { clearTokens } from '@/lib/auth'
const mockClearTokens = clearTokens as ReturnType<typeof vi.fn>

// Helper component to expose context values
function TestConsumer() {
  const { user, isLoading, isAuthenticated, login, logout, refreshUser } = useAuth()
  return (
    <div>
      <div data-testid="loading">{String(isLoading)}</div>
      <div data-testid="authenticated">{String(isAuthenticated)}</div>
      <div data-testid="username">{user?.username ?? 'null'}</div>
      <div data-testid="capabilities">{JSON.stringify(user?.capabilities ?? null)}</div>
      <button onClick={() => login({ id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' })}>
        Login
      </button>
      <button onClick={logout}>Logout</button>
      <button onClick={() => void refreshUser()}>Refresh</button>
    </div>
  )
}

describe('AuthProvider', () => {
  beforeEach(() => {
    mockClearTokens.mockReset()
    mockClearTokens.mockResolvedValue(undefined)
    vi.restoreAllMocks()
  })

  it('starts in loading state and fetches /auth/me on mount', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(null, { status: 401 }))
    render(<AuthProvider><TestConsumer /></AuthProvider>)
    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false')
    })
    expect(screen.getByTestId('authenticated').textContent).toBe('false')
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/auth/me', { credentials: 'same-origin', cache: 'no-store' })
  })

  it('sets user when /auth/me succeeds (cookie is valid)', async () => {
    const mockUser = { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockUser), { status: 200, headers: { 'Content-Type': 'application/json' } })
    )

    render(<AuthProvider><TestConsumer /></AuthProvider>)

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false')
    })
    expect(screen.getByTestId('username').textContent).toBe('admin')
    expect(screen.getByTestId('authenticated').textContent).toBe('true')
  })

  it('sets user=null when /auth/me fails (no valid cookie)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(null, { status: 401 }))

    render(<AuthProvider><TestConsumer /></AuthProvider>)

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false')
    })
    expect(screen.getByTestId('username').textContent).toBe('null')
  })

  it('login updates user state', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(null, { status: 401 }))
    render(<AuthProvider><TestConsumer /></AuthProvider>)
    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false')
    })

    act(() => {
      screen.getByText('Login').click()
    })

    expect(screen.getByTestId('username').textContent).toBe('admin')
    expect(screen.getByTestId('authenticated').textContent).toBe('true')
  })

  it('logout calls clearTokens and sets user=null', async () => {
    const mockUser = { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockUser), { status: 200, headers: { 'Content-Type': 'application/json' } })
    )

    render(<AuthProvider><TestConsumer /></AuthProvider>)
    await waitFor(() => {
      expect(screen.getByTestId('username').textContent).toBe('admin')
    })

    await act(async () => {
      screen.getByText('Logout').click()
    })

    expect(mockClearTokens).toHaveBeenCalled()
    expect(screen.getByTestId('username').textContent).toBe('null')
    expect(screen.getByTestId('authenticated').textContent).toBe('false')
  })

  it('refreshes revoked capabilities on focus and fails closed on network failure', async () => {
    const user = { id: '1', username: 'officer', role: 'viewer', capabilities: ['security.read'] }
    const mockFetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(user)))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...user, capabilities: [] })))
      .mockRejectedValueOnce(new TypeError('network unavailable'))
    render(<AuthProvider><TestConsumer /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('capabilities').textContent).toBe('["security.read"]'))
    act(() => window.dispatchEvent(new Event('focus')))
    await waitFor(() => expect(screen.getByTestId('capabilities').textContent).toBe('[]'))
    await act(async () => { screen.getByText('Refresh').click() })
    expect(screen.getByTestId('authenticated').textContent).toBe('true')
    expect(screen.getByTestId('capabilities').textContent).toBe('[]')
    expect(mockFetch).toHaveBeenCalledTimes(3)
  })

  it('clears authentication on an authoritative 403 refresh', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: '1', username: 'officer' })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'disabled' }), { status: 403 }))
    render(<AuthProvider><TestConsumer /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('authenticated').textContent).toBe('true'))
    await act(async () => { screen.getByText('Refresh').click() })
    expect(screen.getByTestId('authenticated').textContent).toBe('false')
  })

  it('cannot restore an old user from a late initial response after login', async () => {
    let resolve!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => new Promise(r => { resolve = r }))
    render(<AuthProvider><TestConsumer /></AuthProvider>)
    act(() => screen.getByText('Login').click())
    await act(async () => resolve(new Response(JSON.stringify({ username: 'old-session' }))))
    expect(screen.getByTestId('username').textContent).toBe('admin')
  })

  it('never resurrects a session when a refresh finishes across pending logout', async () => {
    let resolveMe!: (response: Response) => void
    let resolveLogout!: () => void
    const mockFetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: '1', username: 'officer' })))
      .mockImplementationOnce(() => new Promise(r => { resolveMe = r }))
    mockClearTokens.mockImplementationOnce(() => new Promise<void>(r => { resolveLogout = r }))
    render(<AuthProvider><TestConsumer /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('authenticated').textContent).toBe('true'))
    act(() => screen.getByText('Refresh').click())
    act(() => screen.getByText('Logout').click())
    expect(screen.getByTestId('authenticated').textContent).toBe('false')
    act(() => { window.dispatchEvent(new Event('focus')); screen.getByText('Refresh').click() })
    expect(mockFetch).toHaveBeenCalledTimes(2)
    await act(async () => { resolveLogout(); resolveMe(new Response(JSON.stringify({ username: 'old-session' }))) })
    expect(screen.getByTestId('authenticated').textContent).toBe('false')
    expect(screen.getByTestId('username').textContent).toBe('null')
  })
})

describe('useAuth outside AuthProvider', () => {
  it('throws an error when used outside AuthProvider', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => render(<TestConsumer />)).toThrow('useAuth must be used within AuthProvider')
    spy.mockRestore()
  })
})
