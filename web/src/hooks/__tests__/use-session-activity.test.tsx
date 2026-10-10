import { act, fireEvent, renderHook } from '@testing-library/react'
import { vi } from 'vitest'
import { apiFetch } from '@/lib/api'
import { useSessionActivity } from '../use-session-activity'

vi.mock('@/lib/api', () => ({ apiFetch: vi.fn() }))
const mockApiFetch = vi.mocked(apiFetch)

async function advance(ms: number) {
  await act(() => vi.advanceTimersByTimeAsync(ms))
}

async function interact(type = 'keydown') {
  await act(async () => { fireEvent(document, new Event(type, { bubbles: true })) })
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-09T20:00:00Z'))
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(false)
  mockApiFetch.mockReset()
  mockApiFetch.mockResolvedValue({})
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})

it('does not renew an unattended visible tab or a signed-out page', async () => {
  const { rerender } = renderHook(({ enabled }) => useSessionActivity(enabled), { initialProps: { enabled: true } })
  await advance(20 * 60_000)
  expect(mockApiFetch).not.toHaveBeenCalled()
  rerender({ enabled: false })
  await interact()
  await advance(60_000)
  expect(mockApiFetch).not.toHaveBeenCalled()
})

it('recognizes typing inside a dialog even when its events stop bubbling', async () => {
  renderHook(() => useSessionActivity(true))
  const dialog = document.createElement('dialog')
  const input = document.createElement('input')
  input.addEventListener('keydown', event => event.stopPropagation())
  dialog.appendChild(input)
  document.body.appendChild(dialog)
  try {
    await act(async () => { fireEvent.keyDown(input, { key: 'a' }) })
    expect(mockApiFetch).toHaveBeenCalledWith('/auth/me', { method: 'HEAD', signal: expect.any(AbortSignal), cache: 'no-store' })
  } finally {
    dialog.remove()
  }
})

it.each(['pointerdown', 'pointermove', 'input', 'wheel', 'scroll', 'touchstart'])('recognizes %s activity', async type => {
  renderHook(() => useSessionActivity(true))
  await interact(type)
  expect(mockApiFetch).toHaveBeenCalledOnce()
})

it('throttles continuous interaction and stops checking once interaction ends', async () => {
  renderHook(() => useSessionActivity(true))
  await interact()
  for (let i = 0; i < 6; i++) {
    await advance(5_000)
    await interact('input')
  }
  expect(mockApiFetch).toHaveBeenCalledTimes(3)
  await advance(60_000)
  const count = mockApiFetch.mock.calls.length
  await advance(20 * 60_000)
  expect(mockApiFetch).toHaveBeenCalledTimes(count)
})

it('ignores hidden-tab activity and requires interaction after returning', async () => {
  renderHook(() => useSessionActivity(true))
  await interact()
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
  fireEvent(document, new Event('visibilitychange'))
  await interact('input')
  await advance(60_000)
  expect(mockApiFetch).toHaveBeenCalledOnce()
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(false)
  fireEvent(document, new Event('visibilitychange'))
  await advance(60_000)
  expect(mockApiFetch).toHaveBeenCalledOnce()
  await interact()
  expect(mockApiFetch).toHaveBeenCalledTimes(2)
})

it('aborts a stalled check and retries while interaction continues', async () => {
  let signal: AbortSignal | undefined
  mockApiFetch.mockImplementationOnce((_path, options) => new Promise((_resolve, reject) => {
    signal = options?.signal as AbortSignal
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
  }))
  renderHook(() => useSessionActivity(true))
  await interact()
  await advance(5_000)
  await interact()
  expect(mockApiFetch).toHaveBeenCalledOnce()
  await advance(5_000)
  expect(signal?.aborted).toBe(true)
  await interact()
  await advance(5_000)
  expect(mockApiFetch).toHaveBeenCalledTimes(2)
})

it('aborts pending checks on hide or unmount and removes activity listeners', async () => {
  const signals: AbortSignal[] = []
  mockApiFetch.mockImplementation((_path, options) => new Promise((_resolve, reject) => {
    const signal = options?.signal as AbortSignal
    signals.push(signal)
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
  }))
  const { unmount } = renderHook(() => useSessionActivity(true))
  await interact()
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
  await act(async () => { fireEvent(document, new Event('visibilitychange')) })
  expect(signals[0].aborted).toBe(true)
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(false)
  await advance(15_000)
  await interact()
  unmount()
  expect(signals[1].aborted).toBe(true)
  await interact()
  await advance(60_000)
  expect(mockApiFetch).toHaveBeenCalledTimes(2)
})
