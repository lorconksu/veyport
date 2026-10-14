import { createContext, useContext, useState, useEffect, useCallback, useMemo, useRef, type ReactNode } from 'react'
import { clearTokens } from '@/lib/auth'
import { apiFetch, ApiError } from '@/lib/api'
import type { User } from '@/types/api'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (user: User) => void
  logout: () => Promise<void>
  refreshUser: () => Promise<User | null>
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: Readonly<{ children: ReactNode }>) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const authorityRevision = useRef(0)
  const sessionEnding = useRef(false)
  const isAuthenticated = !!user

  useEffect(() => {
    // Try to fetch user — cookie is sent automatically.
    // Use raw fetch (not apiFetch) to avoid the 401 → redirect-to-login loop
    // on initial load when no session exists.
    const revision = authorityRevision.current
    let mounted = true
    fetch('/api/auth/me', { credentials: 'same-origin', cache: 'no-store' })
      .then(res => res.ok ? res.json() as Promise<User> : Promise.reject(new Error('not authenticated')))
      .then(fresh => { if (mounted && revision === authorityRevision.current) setUser(fresh) })
      .catch(() => {
        // Not authenticated or cookie expired — no cleanup needed
      })
      .finally(() => { if (mounted) setIsLoading(false) })
    return () => { mounted = false }
  }, [])

  const refreshUser = useCallback(async (): Promise<User | null> => {
    if (sessionEnding.current) return null
    const revision = ++authorityRevision.current
    try {
      const fresh = await apiFetch<User>('/auth/me', { cache: 'no-store' })
      if (revision !== authorityRevision.current) return null
      setUser(fresh)
      return fresh
    } catch (error) {
      if (revision === authorityRevision.current) {
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) setUser(null)
        else setUser(previous => previous && ({ ...previous, capabilities: [] }))
      }
      return null
    }
  }, [])

  useEffect(() => {
    if (!isAuthenticated) return
    const refreshVisible = () => {
      if (document.visibilityState !== 'hidden') void refreshUser()
    }
    globalThis.addEventListener('focus', refreshVisible)
    document.addEventListener('visibilitychange', refreshVisible)
    return () => {
      globalThis.removeEventListener('focus', refreshVisible)
      document.removeEventListener('visibilitychange', refreshVisible)
    }
  }, [isAuthenticated, refreshUser])

  const login = useCallback((user: User) => {
    sessionEnding.current = false
    authorityRevision.current++
    setUser(user)
  }, [])

  const logout = useCallback(async () => {
    sessionEnding.current = true
    const revision = ++authorityRevision.current
    try { await clearTokens() } catch (error) {
      if (revision === authorityRevision.current) sessionEnding.current = false
      throw error
    }
    if (revision === authorityRevision.current) {
      authorityRevision.current++
      sessionEnding.current = false
      setUser(null)
    }
  }, [])

  const contextValue = useMemo(() => ({
    user,
    isLoading,
    isAuthenticated,
    login,
    logout,
    refreshUser,
  }), [user, isLoading, isAuthenticated, login, logout, refreshUser])

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
