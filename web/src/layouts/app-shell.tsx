import { useState, useMemo } from 'react'
import { Outlet, NavLink, useNavigate, Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { LayoutDashboard, ScrollText, Settings, LogOut, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'
import { Logo } from '@/components/logo'
import { getAvatarColor } from '@/lib/avatar'
import { useAllServers } from '@/hooks/use-servers'
import type { AuthStatusResponse } from '@/types/api'

export function AppShell() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [navCollapsed, setNavCollapsed] = useState(false)

  const { data: versionData } = useQuery({
    queryKey: ['app-version'],
    queryFn: () => fetch('/api/auth/status').then(r => r.json()) as Promise<AuthStatusResponse>,
    staleTime: Infinity,
  })
  const version = versionData?.version ?? ''

  const { data: serverData } = useAllServers({ refetchInterval: 30_000 })

  const servers = serverData?.servers ?? []
  const { onlineCount, offlineCount, pendingCount } = useMemo(() => {
    let online = 0, offline = 0, pending = 0
    for (const s of servers) {
      if (s.status === 'online') online++
      else if (s.status === 'offline') offline++
      else if (s.status === 'pending') pending++
    }
    return { onlineCount: online, offlineCount: offline, pendingCount: pending }
  }, [servers])

  const handleLogout = () => {
    queryClient.clear()
    logout()
    navigate('/login')
  }

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Fleet Dashboard' },
    ...(user?.role === 'admin' || user?.role === 'auditor' ? [{ to: '/audit-logs', icon: ScrollText, label: 'Audit Logs' }] : []),
    { to: '/settings', icon: Settings, label: 'Settings' },
  ]

  return (
    <div className="min-h-screen bg-base flex flex-col">
      {/* Top Telemetry Bar */}
      <header className="bg-surface border-b border-border px-4 py-2 flex items-center justify-between text-xs">
        <div className="flex items-center gap-4">
          <Logo layout="horizontal" className="w-40" />
          <span className="text-text-faint">|</span>
          <span className="text-text-muted uppercase tracking-widest text-[10px]">Fleet Health</span>
          <span className="text-status-online">● {onlineCount} Online</span>
          <span className="text-status-offline">● {offlineCount} Offline</span>
          {pendingCount > 0 && (
            <span className="text-status-warning">● {pendingCount} Pending</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Link to="/settings?tab=profile" className="flex items-center gap-2 hover:opacity-80 transition-opacity" title="Profile settings">
            {user?.avatar ? (
              <img src={user.avatar} alt="" className="w-6 h-6 rounded-full object-cover shrink-0" />
            ) : (
              <div
                className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-white shrink-0"
                style={{ backgroundColor: getAvatarColor(user?.username ?? '') }}
              >
                {user?.username?.charAt(0).toUpperCase()}
              </div>
            )}
            <span className="text-text-secondary text-xs">{user?.username}</span>
          </Link>
          <button
            onClick={handleLogout}
            className="text-text-muted hover:text-text-primary transition-colors"
            title="Sign out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </header>

      <div className="flex flex-1">
        {/* Left Sidebar */}
        <nav className={`${navCollapsed ? 'w-12' : 'w-52'} bg-surface/50 border-r border-border flex flex-col py-3 transition-all duration-200 shrink-0`}>
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              title={navCollapsed ? label : undefined}
              className={({ isActive }) =>
                `flex items-center ${navCollapsed ? 'justify-center px-2' : 'gap-3 px-4'} py-2 text-sm transition-colors ${
                  isActive
                    ? 'text-text-primary bg-elevated border-l-2 border-accent'
                    : 'text-text-muted hover:text-text-secondary border-l-2 border-transparent'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              {!navCollapsed && label}
            </NavLink>
          ))}
          <div className="flex-1" />
          <button
            onClick={() => setNavCollapsed(!navCollapsed)}
            className={`flex items-center ${navCollapsed ? 'justify-center px-2' : 'gap-3 px-4'} py-2 text-text-muted hover:text-text-secondary transition-colors`}
            title={navCollapsed ? 'Expand menu' : 'Collapse menu'}
          >
            {navCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            {!navCollapsed && <span className="text-xs">Collapse</span>}
          </button>
          {!navCollapsed && version && <div className="px-4 pt-1 text-[10px] text-text-faint uppercase tracking-widest">v{version}</div>}
        </nav>

        {/* Main Content */}
        <main className="flex-1 overflow-hidden">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
