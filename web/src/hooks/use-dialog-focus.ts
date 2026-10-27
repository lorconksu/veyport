import { useEffect, useRef, type KeyboardEvent } from 'react'

const controls = 'button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]'

export function useDialogFocus(stage = '') {
  const ref = useRef<HTMLElement>(null)
  useEffect(() => {
    const trigger = document.activeElement
    return () => { if (trigger instanceof HTMLElement && trigger.isConnected) trigger.focus() }
  }, [])
  useEffect(() => {
    const root = ref.current
    if (root) (root.querySelector<HTMLElement>(controls) ?? root).focus()
  }, [stage])
  const onKeyDown = (event: KeyboardEvent<HTMLElement>, close: () => void) => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); return }
    if (event.key !== 'Tab') return
    const root = ref.current
    if (!root) return
    const items = [...root.querySelectorAll<HTMLElement>(controls)]
    if (!items.length) { event.preventDefault(); root.focus(); return }
    const first = items[0], last = items[items.length - 1]
    if (event.shiftKey && (document.activeElement === first || document.activeElement === root)) { event.preventDefault(); last.focus() }
    else if (!event.shiftKey && (document.activeElement === last || document.activeElement === root)) { event.preventDefault(); first.focus() }
  }
  return { ref, onKeyDown }
}
