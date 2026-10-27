import { render, screen } from '@testing-library/react'
import { useDialogFocus } from '../use-dialog-focus'

function LoadingDialog({ ready = false }: Readonly<{ ready?: boolean }>) {
  const ref = useDialogFocus(ready ? 'ready' : 'loading')
  return <dialog ref={ref} tabIndex={-1} aria-label="Loading review">{ready ? <button type="button">Review account</button> : <p>Loading account details</p>}</dialog>
}

it('focuses a loading dialog, then its first available action, and returns to the opener', () => {
  const trigger = document.createElement('button')
  trigger.textContent = 'Open review'; document.body.append(trigger); trigger.focus()
  const { rerender, unmount } = render(<LoadingDialog />)
  expect(screen.getByRole('dialog')).toHaveFocus()
  expect(screen.getByRole('dialog')).toHaveAttribute('open')
  rerender(<LoadingDialog ready />)
  expect(screen.getByRole('button', { name: 'Review account' })).toHaveFocus()
  unmount()
  expect(trigger).toHaveFocus()
  trigger.remove()
})

it('closes a dialog safely when its opener has left the document', () => {
  const trigger = document.createElement('button')
  document.body.append(trigger); trigger.focus()
  const { unmount } = render(<LoadingDialog ready />)
  const dialog = screen.getByRole('dialog')
  trigger.remove()
  const focus = vi.spyOn(trigger, 'focus')
  unmount()
  expect(dialog).not.toHaveAttribute('open')
  expect(focus).not.toHaveBeenCalled()
})
