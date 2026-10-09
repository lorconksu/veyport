import { useEffect } from 'react'
import { apiFetch } from '@/lib/api'

const ACTIVITY_WINDOW_MS = 30_000
const CHECK_INTERVAL_MS = 5_000
const REQUEST_INTERVAL_MS = 15_000
const REQUEST_TIMEOUT_MS = 10_000
const activityEvents = ['keydown', 'pointerdown', 'pointermove', 'input', 'wheel', 'scroll', 'touchstart'] as const

// Human interaction can continue while a query is stalled or a dialog is open.
// Keep session checks independent of query polling, and never send them simply
// because an unattended tab is visible. The server remains the expiry authority.
export function useSessionActivity(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return

    let lastActivity = -Infinity
    let lastAttempt = -Infinity
    let currentRequest: AbortController | undefined
    let requestTimeout: ReturnType<typeof setTimeout> | undefined
    let disposed = false

    const checkActivity = () => {
      const now = Date.now()
      if (disposed || document.hidden || currentRequest ||
        now - lastActivity >= ACTIVITY_WINDOW_MS || now - lastAttempt < REQUEST_INTERVAL_MS) return

      lastAttempt = now
      const controller = new AbortController()
      currentRequest = controller
      requestTimeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
      // HEAD runs the same session middleware without downloading the profile
      // (which can contain a large avatar) on every activity check.
      void apiFetch('/auth/me', { method: 'HEAD', signal: controller.signal, cache: 'no-store' })
        .catch(() => {
          // Network failures do not prove the session expired. A subsequent
          // active check can retry; apiFetch handles an actual auth refusal.
        })
        .finally(() => {
          clearTimeout(requestTimeout)
          currentRequest = undefined
        })
    }

    const recordActivity = () => {
      if (document.hidden) return
      lastActivity = Date.now()
      checkActivity()
    }
    const onVisibilityChange = () => {
      // Returning to the tab alone does not count as renewed interaction.
      if (document.hidden) {
        lastActivity = -Infinity
        currentRequest?.abort()
      }
    }

    for (const event of activityEvents) document.addEventListener(event, recordActivity, { capture: true, passive: true })
    document.addEventListener('visibilitychange', onVisibilityChange)
    const interval = setInterval(checkActivity, CHECK_INTERVAL_MS)
    return () => {
      disposed = true
      clearInterval(interval)
      clearTimeout(requestTimeout)
      currentRequest?.abort()
      for (const event of activityEvents) document.removeEventListener(event, recordActivity, true)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [enabled])
}
