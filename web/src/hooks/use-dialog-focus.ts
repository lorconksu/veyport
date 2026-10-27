import { useEffect, useRef } from 'react'

const controls = 'button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]'

export function useDialogFocus(stage = '') {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    const trigger = document.activeElement
    dialog?.showModal()
    return () => {
      dialog?.close()
      if (trigger instanceof HTMLElement && trigger.isConnected) trigger.focus()
    }
  }, [])
  useEffect(() => {
    const root = ref.current
    if (root) (root.querySelector<HTMLElement>(controls) ?? root).focus()
  }, [stage])
  return ref
}
