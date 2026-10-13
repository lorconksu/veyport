import { render, screen, waitFor } from '@testing-library/react'
import { Outlet } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import App from '../App'

vi.mock('@/hooks/use-auth', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
  useAuth: vi.fn(),
}))
vi.mock('@/layouts/app-shell', () => ({ AppShell: () => <Outlet /> }))
vi.mock('@/pages/dashboard', () => ({ DashboardPage: () => <div>Capability dashboard</div> }))
vi.mock('@/pages/audit-logs', () => ({ AuditLogsPage: () => <div>Capability audit view</div> }))

const mockUseAuth = vi.mocked(useAuth)

afterEach(() => { window.history.replaceState({}, '', '/') })

it.each([
  ['viewer', ['audit.read'], true],
  ['admin', [], false],
  ['viewer', ['security.read'], false],
] as const)('actual audit route honors server capabilities for %s / %j', async (role, capabilities, allowed) => {
  mockUseAuth.mockReturnValue({
    user: { id: 'u', username: 'principal', role, capabilities: [...capabilities], email: '', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
    isAuthenticated: true, isLoading: false, login: vi.fn(), logout: vi.fn(), refreshUser: vi.fn(),
  })
  window.history.replaceState({}, '', '/audit-logs')
  render(<App />)
  await waitFor(() => expect(screen.getByText(allowed ? 'Capability audit view' : 'Capability dashboard')).toBeInTheDocument())
  expect(window.location.pathname).toBe(allowed ? '/audit-logs' : '/')
})
