import { useCallback, useEffect, useRef, useState } from 'react'

// Decisions and one-use reads remain outside query/mutation caches. Every
// continuation must observe cancellation before requesting its next effect.
export function useSensitiveTask(timeoutMs = 30_000) {
  const active = useRef<AbortController | null>(null)
  const mounted = useRef(true)
  const [busy, setBusy] = useState(false)
  const cancel = useCallback(() => {
    active.current?.abort()
    active.current = null
    if (mounted.current) setBusy(false)
  }, [])
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; cancel() }
  }, [cancel])
  const run = useCallback(async <T,>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> => {
    cancel()
    const controller = new AbortController()
    active.current = controller
    setBusy(true)
    const timeout = setTimeout(() => controller.abort(new Error('Protected operation timed out; check current status')), timeoutMs)
    try {
      const result = await operation(controller.signal)
      controller.signal.throwIfAborted()
      return result
    } finally {
      clearTimeout(timeout)
      if (active.current === controller) {
        active.current = null
        if (mounted.current) setBusy(false)
      }
    }
  }, [cancel, timeoutMs])
  return { run, cancel, busy }
}
