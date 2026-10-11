import React, { Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from '@/lib/query-client'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { hasCapability } from '@/lib/auth'
import { AuthLayout } from '@/layouts/auth-layout'
import { AppShell } from '@/layouts/app-shell'

// Route-level code splitting: lazy-load page components
const LoginPage = React.lazy(() => import('@/pages/login').then(m => ({ default: m.LoginPage })))
const LoginTOTPPage = React.lazy(() => import('@/pages/login-totp').then(m => ({ default: m.LoginTOTPPage })))
const SetupPage = React.lazy(() => import('@/pages/setup').then(m => ({ default: m.SetupPage })))
const SetupTOTPPage = React.lazy(() => import('@/pages/setup-totp').then(m => ({ default: m.SetupTOTPPage })))
const DashboardPage = React.lazy(() => import('@/pages/dashboard').then(m => ({ default: m.DashboardPage })))
const AuditLogsPage = React.lazy(() => import('@/pages/audit-logs').then(m => ({ default: m.AuditLogsPage })))
const SettingsPage = React.lazy(() => import('@/pages/settings').then(m => ({ default: m.SettingsPage })))
const ServerDetailPage = React.lazy(() => import('@/pages/server-detail').then(m => ({ default: m.ServerDetailPage })))

const LazyFallback = <div className="p-8 text-center">Loading...</div>

function ProtectedRoute({ children }: Readonly<{ children: React.ReactNode }>) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen bg-base flex items-center justify-center">
        <div className="text-text-muted text-sm">Loading...</div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function AuditRoute({ children }: Readonly<{ children: React.ReactNode }>) {
  const { user } = useAuth()

  if (!hasCapability(user, 'audit.read')) {
    return <Navigate to="/" replace />
  }

  return <>{children}</>
}

function AppRoutes() {
  return (
    <Routes>
      {/* Public auth routes */}
      <Route element={<AuthLayout />}>
        <Route path="/login" element={<Suspense fallback={LazyFallback}><LoginPage /></Suspense>} />
        <Route path="/login/totp" element={<Suspense fallback={LazyFallback}><LoginTOTPPage /></Suspense>} />
        <Route path="/setup" element={<Suspense fallback={LazyFallback}><SetupPage /></Suspense>} />
        <Route path="/setup/totp" element={<Suspense fallback={LazyFallback}><SetupTOTPPage /></Suspense>} />
      </Route>

      {/* Protected routes */}
      <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
        <Route path="/" element={<Suspense fallback={LazyFallback}><DashboardPage /></Suspense>} />
        <Route path="/audit-logs" element={<Suspense fallback={LazyFallback}><AuditRoute><AuditLogsPage /></AuditRoute></Suspense>} />
        <Route path="/settings" element={<Suspense fallback={LazyFallback}><SettingsPage /></Suspense>} />
        <Route path="/servers/:id" element={<Suspense fallback={LazyFallback}><ServerDetailPage /></Suspense>} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
