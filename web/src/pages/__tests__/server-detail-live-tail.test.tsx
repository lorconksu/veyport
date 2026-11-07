import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ServerDetailPage } from '../server-detail'
import { apiFetch } from '@/lib/api'

// Only unrelated application services are replaced. LiveTail, fetch response
// readers, the SSE assembler, cookie lookup, and the page's start/stop flow run.
vi.mock('@/lib/api', () => ({ apiFetch: vi.fn(), listPendingReEnroll: vi.fn().mockResolvedValue([]) }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: { id: 'u1', role: 'user' } }) }))
vi.mock('@/components/server-terminal', () => ({ ServerTerminal: () => null, OfflineTerminalState: () => null }))

const encoder = new TextEncoder()
const filePath = '/var/log/app & worker.log'
const fetchMock = vi.fn<typeof fetch>()
const scrollIntoView = vi.fn()
const originalScrollIntoView = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollIntoView')
let frames: Map<number, FrameRequestCallback>
let nextFrame: number
let client: QueryClient

function stream() {
  let controller!: ReadableStreamDefaultController<Uint8Array>
  const body = new ReadableStream<Uint8Array>({ start(value) { controller = value } })
  return { body, controller, response: new Response(body, { headers: { 'Content-Type': 'text/event-stream' } }) }
}

function frame(text: string | Uint8Array): string {
  const bytes = typeof text === 'string' ? encoder.encode(text) : text
  return `data: ${btoa(Array.from(bytes, byte => String.fromCodePoint(byte)).join(''))}\n\n`
}

async function settle(action: () => void = () => {}) {
  await act(async () => { action() })
}

async function flushFrame() {
  await settle(() => {
    const pending = [...frames.values()]
    frames.clear()
    pending.forEach(callback => callback(0))
  })
}

async function startTail() {
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/servers/srv-1']}>
        <Routes><Route path="/servers/:id" element={<ServerDetailPage />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  fireEvent.click(await screen.findByText('/var/log'))
  fireEvent.click(await screen.findByText('app & worker.log'))
  fireEvent.click(await screen.findByTitle('Start live tail'))
  await settle()
  return view
}

function signalFor(index = 0): AbortSignal {
  return fetchMock.mock.calls[index][1]!.signal as AbortSignal
}

beforeEach(() => {
  frames = new Map()
  nextFrame = 0
  scrollIntoView.mockClear()
  vi.stubGlobal('fetch', fetchMock.mockReset())
  vi.stubGlobal('requestAnimationFrame', vi.fn((callback: FrameRequestCallback) => {
    frames.set(++nextFrame, callback)
    return nextFrame
  }))
  vi.stubGlobal('cancelAnimationFrame', vi.fn((id: number) => { frames.delete(id) }))
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: scrollIntoView })
  sessionStorage.clear()
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  vi.mocked(apiFetch).mockImplementation(async (path) => {
    if (path === '/servers/srv-1') return { id: 'srv-1', name: 'Logs server', status: 'online', hostname: 'logs', labels: '' } as never
    if (path.endsWith('/my-paths')) return { paths: ['/var/log'] } as never
    if (path.includes('/files?')) return { files: [{ name: 'app & worker.log', path: filePath, is_dir: false, readable: true, size: 7 }] } as never
    if (path.includes('/files/read?')) return { data: btoa('preview'), total_size: 7, mime_type: 'text/plain' } as never
    throw new Error(`Unexpected API call: ${path}`)
  })
})

afterEach(() => {
  cleanup()
  client.clear()
  vi.useRealTimers()
  vi.restoreAllMocks()
  if (originalScrollIntoView) Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', originalScrollIntoView)
  else Reflect.deleteProperty(HTMLElement.prototype, 'scrollIntoView')
  vi.unstubAllGlobals()
})

describe('LiveTail connection isolation regressions', () => {
  it('discards unpainted lines and cancels their frame when grep reconnects', async () => {
    const old = stream()
    const current = stream()
    fetchMock.mockResolvedValueOnce(old.response).mockResolvedValueOnce(current.response)
    await startTail()
    await settle(() => old.controller.enqueue(encoder.encode(frame('old buffered line\n'))))
    expect(frames.size).toBe(1)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    fireEvent.change(screen.getByPlaceholderText('Filter (grep)...'), { target: { value: 'new' } })
    await act(async () => { vi.advanceTimersByTime(500) })
    expect(signalFor(0).aborted).toBe(true)
    expect(frames.size).toBe(0)
    await settle(() => current.controller.enqueue(encoder.encode(frame('new matching line\n'))))
    expect(frames.size).toBe(1)
    await flushFrame()
    expect(screen.getByText('new matching line')).toBeInTheDocument()
    expect(screen.queryByText('old buffered line')).not.toBeInTheDocument()
    expect(screen.getByText('1 line')).toBeInTheDocument()
  })

  it('ignores old reader data and EOF after a replacement connection starts', async () => {
    const old = stream()
    const current = stream()
    fetchMock.mockResolvedValueOnce(old.response).mockResolvedValueOnce(current.response)
    await startTail()
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    fireEvent.change(screen.getByPlaceholderText('Filter (grep)...'), { target: { value: 'fresh' } })
    await act(async () => { vi.advanceTimersByTime(500) })
    await settle(() => { old.controller.enqueue(encoder.encode(frame('stale line\n'))); old.controller.close() })
    await flushFrame()
    expect(screen.getByText('Streaming')).toBeInTheDocument()
    expect(screen.queryByText('stale line')).not.toBeInTheDocument()
    expect(screen.getByText('Waiting for log data...')).toBeInTheDocument()
  })

  it('ignores a fetch response that resolves after its connection was aborted', async () => {
    const old = stream()
    const current = stream()
    let resolveOld!: (response: Response) => void
    fetchMock.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve })).mockResolvedValueOnce(current.response)
    await startTail()
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    fireEvent.change(screen.getByPlaceholderText('Filter (grep)...'), { target: { value: 'fresh' } })
    await act(async () => { vi.advanceTimersByTime(500) })
    await settle(() => { old.controller.enqueue(encoder.encode(frame('late stale line\n'))); old.controller.close(); resolveOld(old.response) })
    await flushFrame()
    expect(screen.getByText('Streaming')).toBeInTheDocument()
    expect(screen.queryByText('late stale line')).not.toBeInTheDocument()
    expect(old.body.locked).toBe(false)
  })

  it('keeps only the newest 2,000 lines during a burst larger than an argument list', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    // This also catches spreading an unbounded batch into Array.push, which
    // throws before any log lines can be painted for a sufficiently large read.
    const burst = Array.from({ length: 150_000 }, (_, index) => `burst ${index}`).join('\n') + '\n'
    await settle(() => live.controller.enqueue(encoder.encode(frame(burst))))
    await flushFrame()
    expect(screen.getByText('Streaming')).toBeInTheDocument()
    expect(screen.getByText('2,000 lines')).toBeInTheDocument()
    expect(screen.queryByText('burst 147999')).not.toBeInTheDocument()
    expect(screen.getByText('burst 148000')).toBeInTheDocument()
    expect(screen.getByText('burst 149999')).toBeInTheDocument()
  })
})

describe('LiveTail streaming through the server detail page', () => {
  it('connects with the encoded path, CSRF cookie and same-origin credentials', async () => {
    const live = stream()
    let connect!: (response: Response) => void
    vi.spyOn(document, 'cookie', 'get').mockReturnValue('other=value; __Host-veyport_csrf=csrf-token')
    fetchMock.mockImplementationOnce(() => new Promise(resolve => { connect = resolve }))
    await startTail()
    expect(screen.getByText('Connecting')).toBeInTheDocument()
    expect(screen.getByText('Connecting to log stream...')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      `/api/servers/srv-1/logs/tail?${new URLSearchParams({ path: filePath })}`,
      { headers: { 'X-CSRF-Token': 'csrf-token' }, credentials: 'same-origin', signal: expect.any(AbortSignal) },
    )
    expect(signalFor().aborted).toBe(false)
    await settle(() => connect(live.response))
    expect(screen.getByText('Streaming')).toBeInTheDocument()
    expect(screen.getByText('Waiting for log data...')).toBeInTheDocument()
  })

  it('reassembles chunked SSE and split UTF-8 payloads, skips notices, and flushes a final partial line at EOF', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    const utf8 = encoder.encode('first café\n<img src=x> final partial')
    const split = utf8.indexOf(0xc3) + 1
    const wire = ': heartbeat\n\nevent: overflow\ndata: {"dropped":1}\n\ndata: not-base64!\n\n' + frame(utf8.slice(0, split)) + frame(utf8.slice(split))
    await settle(() => {
      // Neither browser reads nor SSE frames need to align with file lines.
      for (let offset = 0; offset < wire.length; offset += 7) {
        live.controller.enqueue(encoder.encode(wire.slice(offset, offset + 7)))
      }
    })
    expect(screen.queryByText('first café')).not.toBeInTheDocument()
    expect(frames.size).toBe(1)
    await flushFrame()
    expect(screen.getByText('first café')).toBeInTheDocument()
    expect(screen.getByText('1 line')).toBeInTheDocument()
    expect(screen.queryByText('<img src=x> final partial')).not.toBeInTheDocument()
    await settle(() => live.controller.close())
    await flushFrame()
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
    expect(screen.getByText('<img src=x> final partial')).toBeInTheDocument()
    expect(screen.getByText('2 lines')).toBeInTheDocument()
    expect(document.querySelector('pre img')).toBeNull()
    expect(screen.queryByText(/dropped/)).not.toBeInTheDocument()
  })

  it('disconnects cleanly when an empty stream ends', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    await settle(() => live.controller.close())
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
    expect(screen.getByText('0 lines')).toBeInTheDocument()
    expect(frames.size).toBe(0)
    expect(screen.queryByText('Waiting for log data...')).not.toBeInTheDocument()
  })

  it.each([
    ['server JSON error', () => new Response(JSON.stringify({ error: 'Log access denied' }), { status: 403 }), 'Log access denied'],
    ['JSON without an error', () => new Response('{}', { status: 503 }), 'HTTP 503'],
    ['non-JSON HTTP error', () => new Response('<html>Bad gateway</html>', { status: 502 }), 'HTTP 502'],
    ['missing response body', () => new Response(null), 'Response body is not readable'],
  ])('shows %s and disconnects', async (_label, response, message) => {
    fetchMock.mockResolvedValueOnce(response())
    await startTail()
    expect(screen.getByText(message)).toBeInTheDocument()
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
    expect(screen.getByText('0 lines')).toBeInTheDocument()
    expect(frames.size).toBe(0)
  })

  it.each([
    ['fetch rejection', new Error('Network unavailable'), 'Network unavailable'],
    ['non-Error rejection', 'unknown rejection', 'Connection failed'],
  ])('shows a %s', async (_label, rejection, message) => {
    fetchMock.mockRejectedValueOnce(rejection)
    await startTail()
    expect(screen.getByText(message)).toBeInTheDocument()
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
  })

  it('reports a locked body reader instead of waiting forever', async () => {
    const live = stream()
    const lock = live.body.getReader()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
    expect(screen.getByText(/ReadableStream is locked/)).toBeInTheDocument()
    lock.releaseLock()
  })

  it('reports reader failures and preserves already rendered output', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    await settle(() => live.controller.enqueue(encoder.encode(frame('before failure\n'))))
    await flushFrame()
    await settle(() => live.controller.error(new Error('Stream interrupted')))
    expect(screen.getByText('Stream interrupted')).toBeInTheDocument()
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
    expect(screen.getByText('before failure')).toBeInTheDocument()
  })

  it.each(['internal', 'toolbar'])('aborts and clears pending work when the %s Stop button is clicked', async (button) => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    await settle(() => live.controller.enqueue(encoder.encode(frame('unpainted\n'))))
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    fireEvent.change(screen.getByPlaceholderText('Filter (grep)...'), { target: { value: 'pending filter' } })
    expect(vi.getTimerCount()).toBe(1)
    const stop = button === 'toolbar' ? screen.getByTitle('Stop live tail') : screen.getAllByRole('button', { name: 'Stop' }).find(element => !element.title)!
    fireEvent.click(stop)
    expect(vi.getTimerCount()).toBe(0)
    expect(signalFor().aborted).toBe(true)
    expect(frames.size).toBe(0)
    expect(screen.getByTitle('Start live tail')).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('Filter (grep)...')).not.toBeInTheDocument()
    await act(async () => { vi.advanceTimersByTime(500) })
    await settle(() => live.controller.error(new DOMException('Aborted', 'AbortError')))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Aborted')).not.toBeInTheDocument()
  })

  it('aborts on page unmount, cancels RAF and debounce, and ignores late reader completion', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    const view = await startTail()
    await settle(() => live.controller.enqueue(encoder.encode(frame('pending at unmount\n'))))
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    fireEvent.change(screen.getByPlaceholderText('Filter (grep)...'), { target: { value: 'pending filter' } })
    expect(vi.getTimerCount()).toBe(1)
    view.unmount()
    expect(vi.getTimerCount()).toBe(0)
    expect(signalFor().aborted).toBe(true)
    expect(frames.size).toBe(0)
    await act(async () => { vi.advanceTimersByTime(500) })
    await settle(() => { live.controller.enqueue(encoder.encode(frame('late data\n'))); live.controller.close() })
    expect(frames.size).toBe(0)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('debounces the latest grep for 500ms, reconnects with encoded filters, clears output, and removes cleared grep', async () => {
    const first = stream()
    const second = stream()
    const third = stream()
    vi.spyOn(document, 'cookie', 'get').mockReturnValue('other=value')
    fetchMock.mockResolvedValueOnce(first.response).mockResolvedValueOnce(second.response).mockResolvedValueOnce(third.response)
    await startTail()
    expect(fetchMock.mock.calls[0][1]?.headers).toBeUndefined()
    await settle(() => first.controller.enqueue(encoder.encode(frame('old rendered output\n'))))
    await flushFrame()
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const input = screen.getByPlaceholderText('Filter (grep)...')
    fireEvent.change(input, { target: { value: 'intermediate' } })
    await act(async () => { vi.advanceTimersByTime(250) })
    fireEvent.change(input, { target: { value: 'error .* & worker' } })
    await act(async () => { vi.advanceTimersByTime(499) })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(signalFor().aborted).toBe(false)
    await act(async () => { vi.advanceTimersByTime(1) })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(signalFor().aborted).toBe(true)
    const filteredUrl = new URL(fetchMock.mock.calls[1][0] as string, 'https://veyport.test')
    expect(filteredUrl.searchParams.get('grep')).toBe('error .* & worker')
    expect(filteredUrl.searchParams.get('path')).toBe(filePath)
    expect(screen.queryByText('old rendered output')).not.toBeInTheDocument()
    expect(screen.getByText('0 lines')).toBeInTheDocument()
    fireEvent.change(input, { target: { value: '' } })
    await act(async () => { vi.advanceTimersByTime(500) })
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(signalFor(1).aborted).toBe(true)
    expect(new URL(fetchMock.mock.calls[2][0] as string, 'https://veyport.test').searchParams.has('grep')).toBe(false)
  })

  it('keeps receiving lines while paused and scrolls only when enabled and near the bottom', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    await settle(() => live.controller.enqueue(encoder.encode(frame('initial line\n'))))
    await flushFrame()
    expect(scrollIntoView).toHaveBeenLastCalledWith({ block: 'end' })
    scrollIntoView.mockClear()
    fireEvent.click(screen.getByTitle('Pause auto-scroll'))
    expect(screen.getByRole('button', { name: 'Paused' })).toBeInTheDocument()
    await settle(() => live.controller.enqueue(encoder.encode(frame('while paused\n'))))
    await flushFrame()
    expect(screen.getByText('while paused')).toBeInTheDocument()
    expect(scrollIntoView).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTitle('Resume auto-scroll'))
    expect(scrollIntoView).toHaveBeenCalledTimes(1)
    scrollIntoView.mockClear()
    const container = screen.getByText('initial line').closest('pre')!.parentElement!
    Object.defineProperties(container, { scrollHeight: { configurable: true, value: 1000 }, clientHeight: { configurable: true, value: 100 }, scrollTop: { configurable: true, value: 0, writable: true } })
    fireEvent.scroll(container)
    await settle(() => live.controller.enqueue(encoder.encode(frame('while scrolled up\n'))))
    await flushFrame()
    expect(screen.getByText('while scrolled up')).toBeInTheDocument()
    expect(scrollIntoView).not.toHaveBeenCalled()
    container.scrollTop = 900
    fireEvent.scroll(container)
    await settle(() => live.controller.enqueue(encoder.encode(frame('back at bottom\n'))))
    await flushFrame()
    expect(scrollIntoView).toHaveBeenCalledTimes(1)
  })

  it('retains the newest 2,000 rendered lines across multiple animation frames', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    await settle(() => live.controller.enqueue(encoder.encode(frame(Array.from({ length: 2000 }, (_, index) => `line ${index}`).join('\n') + '\n'))))
    await flushFrame()
    expect(screen.getByText('2,000 lines')).toBeInTheDocument()
    await settle(() => live.controller.enqueue(encoder.encode(frame('new last line\n'))))
    await flushFrame()
    expect(screen.getByText('2,000 lines')).toBeInTheDocument()
    expect(screen.queryByText('line 0')).not.toBeInTheDocument()
    expect(screen.getByText('line 1')).toBeInTheDocument()
    expect(screen.getByText('new last line')).toBeInTheDocument()
  })
})


describe('LiveTail buffered reads', () => {
  it('coalesces multiple reads while animation frames are stalled and keeps the newest lines', async () => {
    const live = stream()
    fetchMock.mockResolvedValueOnce(live.response)
    await startTail()
    for (let batch = 0; batch < 3; batch++) {
      await settle(() => live.controller.enqueue(encoder.encode(frame(
        Array.from({ length: 1000 }, (_, index) => `buffered ${batch * 1000 + index}`).join('\n') + '\n',
      ))))
      expect(frames.size).toBe(1)
    }
    expect(screen.getByText('0 lines')).toBeInTheDocument()
    await flushFrame()
    expect(screen.getByText('2,000 lines')).toBeInTheDocument()
    expect(screen.queryByText('buffered 999')).not.toBeInTheDocument()
    expect(screen.getByText('buffered 1000')).toBeInTheDocument()
    expect(screen.getByText('buffered 2999')).toBeInTheDocument()
  })

  it("does not flush a previous connection's partial line at EOF after reconnect", async () => {
    const old = stream()
    const current = stream()
    fetchMock.mockResolvedValueOnce(old.response).mockResolvedValueOnce(current.response)
    await startTail()
    await settle(() => old.controller.enqueue(encoder.encode(frame('old partial without newline'))))
    expect(frames.size).toBe(0)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    fireEvent.change(screen.getByPlaceholderText('Filter (grep)...'), { target: { value: 'current' } })
    await act(async () => { vi.advanceTimersByTime(500) })
    await settle(() => old.controller.close())
    await flushFrame()
    expect(screen.getByText('Streaming')).toBeInTheDocument()
    expect(screen.queryByText('old partial without newline')).not.toBeInTheDocument()
    expect(screen.getByText('0 lines')).toBeInTheDocument()
  })
})
