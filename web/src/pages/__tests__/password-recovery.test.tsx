import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { PasswordRecoveryForm } from '../password-recovery'
import { apiFetchWithToken } from '@/lib/api'

vi.mock('@/lib/api', () => ({ apiFetchWithToken: vi.fn() }))
const request = vi.mocked(apiFetchWithToken)
const recovery = { must_change_password: true, recovery_token: 'fixture-recovery-authority', expires_at: '2026-12-01T12:00:00Z' } as const
const strongPassword = 'Permanent#Strong2026'
function setup() {
  const complete = vi.fn(), cancel = vi.fn()
  const view = render(<PasswordRecoveryForm recovery={recovery} onComplete={complete} onCancel={cancel} />)
  return { ...view, complete, cancel }
}
function fill(password = strongPassword, confirmation = password) {
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: password } })
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: confirmation } })
}
beforeEach(() => { request.mockReset() })

it.each([
  ['weak', 'weak', 'At least 12 characters'],
  [strongPassword, 'Different#Strong2026', 'Passwords do not match.'],
])('refuses invalid form submission before contacting recovery: %s', (password, confirmation, message) => {
  setup(); fill(password, confirmation)
  expect(screen.getByText(message)).toBeInTheDocument()
  const button = screen.getByRole('button', { name: 'Change password and return to sign-in' })
  expect(button).toBeDisabled()
  fireEvent.submit(button.closest('form')!)
  expect(request).not.toHaveBeenCalled()
})

it('prevents duplicate completion, keeps authority private and aborts cancellation without late success', async () => {
  let finish!: (response: unknown) => void
  request.mockReturnValue(new Promise(resolve => { finish = resolve }))
  const { complete, cancel, unmount } = setup(); fill()
  fireEvent.click(screen.getByRole('button', { name: 'Change password and return to sign-in' }))
  const pending = await screen.findByRole('button', { name: 'Changing...' })
  expect(pending).toBeDisabled()
  fireEvent.submit(pending.closest('form')!)
  expect(request).toHaveBeenCalledTimes(1)
  expect(screen.queryByText(recovery.recovery_token)).not.toBeInTheDocument()
  const signal = request.mock.calls[0][2]?.signal
  fireEvent.click(screen.getByRole('button', { name: 'Cancel and return to sign-in' }))
  expect(signal?.aborted).toBe(true)
  expect(cancel).toHaveBeenCalledTimes(1)
  expect(screen.getByLabelText('New password')).toHaveValue('')
  expect(screen.getByLabelText('Confirm new password')).toHaveValue('')
  unmount()
  await act(async () => finish({ requires_login: true }))
  expect(complete).not.toHaveBeenCalled()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('does not misreport an aborted recovery request as a password or authentication refusal', async () => {
  request.mockRejectedValue(new DOMException('Request cancelled', 'AbortError'))
  const { complete } = setup(); fill()
  fireEvent.click(screen.getByRole('button', { name: 'Change password and return to sign-in' }))
  await waitFor(() => expect(request).toHaveBeenCalledTimes(1))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Change password and return to sign-in' })).toBeEnabled())
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  expect(complete).not.toHaveBeenCalled()
})

it('aborts recovery on unmount and ignores a late completed request', async () => {
  let finish!: (response: unknown) => void
  request.mockReturnValue(new Promise(resolve => { finish = resolve }))
  const { complete, unmount } = setup(); fill()
  fireEvent.click(screen.getByRole('button', { name: 'Change password and return to sign-in' }))
  await waitFor(() => expect(request).toHaveBeenCalledTimes(1))
  const signal = request.mock.calls[0][2]?.signal
  unmount()
  expect(signal?.aborted).toBe(true)
  await act(async () => finish({ requires_login: true }))
  expect(complete).not.toHaveBeenCalled()
})
