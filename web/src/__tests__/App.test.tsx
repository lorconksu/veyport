import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuth } from '@/hooks/use-auth'
import App from '../App'
import { queryClient } from '@/lib/query-client'

vi.mock('@/hooks/use-auth', () => ({ AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>, useAuth: vi.fn() }))
vi.mock('@/lib/api', () => ({ apiFetch: vi.fn(() => new Promise(() => {})), apiFetchOnce: vi.fn() }))
vi.mock('@/layouts/app-shell', async () => { const { Outlet } = await import('react-router-dom'); return { AppShell: () => <Outlet /> } })
vi.mock('@/pages/dashboard', () => ({ DashboardPage: () => <div>Protected dashboard</div> }))
vi.mock('@/pages/login', async () => { const { useLocation } = await import('react-router-dom'); return { LoginPage: () => { const location = useLocation(); return <div>Login Page <span data-testid="login-return">{location.state?.returnTo}</span></div> } } })
const auth = vi.mocked(useAuth)
const signedOut = { user: null, isLoading: false, isAuthenticated: false, login: vi.fn(), logout: vi.fn(), refreshUser: vi.fn() }
beforeEach(() => { window.history.replaceState({}, '', '/'); auth.mockReturnValue(signedOut); queryClient.clear() })
afterEach(() => { window.history.replaceState({}, '', '/'); queryClient.clear() })

describe('real App routing', () => {
  it('redirects an unauthenticated dashboard visitor to login', async () => { render(<App />); await screen.findByText('Login Page'); expect(window.location.pathname).toBe('/login') })
  it('shows loading while authentication is unresolved', () => { auth.mockReturnValue({ ...signedOut, isLoading: true }); render(<App />); expect(screen.getByText('Loading...')).toBeInTheDocument() })
  it('renders the protected dashboard after authentication', async () => { auth.mockReturnValue({ ...signedOut, user: { id: '1', username: 'admin', email: 'a@b.test', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }, isAuthenticated: true }); render(<App />); await screen.findByText('Protected dashboard'); expect(window.location.pathname).toBe('/') })
  it('preserves only the narrow app launch route through login', async () => { window.history.replaceState({}, '', '/applications/abc/launch?path=%2Fnative'); render(<App />); await screen.findByText('Login Page'); await waitFor(() => expect(screen.getByTestId('login-return')).toHaveTextContent('/applications/abc/launch?path=%2Fnative')) })
  it('does not preserve an arbitrary dashboard route as a login return', async () => { window.history.replaceState({}, '', '/settings'); render(<App />); await screen.findByText('Login Page'); expect(screen.getByTestId('login-return')).toHaveTextContent('/') })
})
