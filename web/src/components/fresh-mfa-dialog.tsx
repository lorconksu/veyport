import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useSensitiveTask } from '@/hooks/use-sensitive-task'

export function FreshMFADialog({ title, children, onClose, onSubmit, onSuccess }: {
  title: string
  children: ReactNode
  onClose: () => void
  onSubmit: (code: string, signal: AbortSignal) => Promise<void>
  onSuccess: () => void
}) {
  const input = useRef<HTMLInputElement>(null)
  const cancel = useRef<HTMLButtonElement>(null)
  const confirm = useRef<HTMLButtonElement>(null)
  const previous = useRef(document.activeElement)
  useEffect(() => {
    input.current?.focus()
    return () => { const control = previous.current; if (control instanceof HTMLElement && control.isConnected) control.focus() }
  }, [])
  const [code, setCode] = useState('')
  const [failure, setFailure] = useState(false)
  const task = useSensitiveTask()
  const submit = async () => {
    const freshCode = code
    setCode('')
    try {
      await task.run(signal => onSubmit(freshCode, signal))
      onSuccess()
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return
      setFailure(true)
    }
  }
  return <div role="dialog" aria-modal="true" aria-labelledby="fresh-mfa-title" onKeyDown={event => {
    if (event.key === 'Escape') onClose()
    if (event.key === 'Tab') {
      const items = [input.current, cancel.current, confirm.current].filter((control): control is HTMLInputElement | HTMLButtonElement => !!control && !control.disabled)
      if (!items.length) return
      const first = items[0], last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
  }} className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
    <div className="w-full max-w-2xl max-h-[90vh] overflow-auto rounded border border-border bg-surface p-5 space-y-3">
      <h3 id="fresh-mfa-title" className="text-base font-semibold text-text-primary">{title}</h3>
      {children}
      {failure ? <p role="alert" className="text-sm text-status-error">The operation was refused or could not be confirmed. Close this review and check current status before starting again. The proof will not be reused.</p> : <label className="block text-sm text-text-secondary">Fresh MFA code<input ref={input} type="password" inputMode="numeric" autoComplete="off" maxLength={6} value={code} disabled={task.busy} onChange={event => setCode(event.target.value.replace(/\D/g, ''))} className="block mt-1 w-full rounded border border-border bg-elevated px-3 py-2" /></label>}
      {task.busy && <p role="status" className="text-sm text-text-muted">Submitting this exact operation…</p>}
      <div className="flex justify-end gap-2"><button ref={cancel} type="button" onClick={onClose} className="rounded border border-border px-3 py-2 text-sm">{failure ? 'Close review' : 'Cancel'}</button>{!failure && <button ref={confirm} type="button" disabled={task.busy || !/^\d{6}$/.test(code)} onClick={() => void submit()} className="rounded bg-accent px-3 py-2 text-sm text-white disabled:opacity-50">Confirm with fresh MFA</button>}</div>
    </div>
  </div>
}
