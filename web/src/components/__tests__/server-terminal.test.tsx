import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { OfflineTerminalState, ServerTerminal } from '../server-terminal'
import { apiFetch } from '@/lib/api'
import type { Server } from '@/types/api'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

const terminalMocks = vi.hoisted(() => {
  const terminalInstances: MockTerminal[] = []
  const fitInstances: MockFitAddon[] = []
  const eventSources: MockEventSource[] = []
  const resizeObservers: MockResizeObserver[] = []

  class MockTerminal {
    cols = 100
    rows = 30
    dataHandler: ((data: string) => void) | null = null
    disposed = false
    focused = false
    opened = false
    resetCount = 0
    writes: unknown[] = []
    writelnCalls: string[] = []

    constructor() {
      terminalInstances.push(this)
    }

    loadAddon() {}

    open() {
      this.opened = true
    }

    focus() {
      this.focused = true
    }

    reset() {
      this.resetCount += 1
    }

    write(data: unknown) {
      this.writes.push(data)
    }

    writeln(data: string) {
      this.writelnCalls.push(data)
    }

    onData(handler: (data: string) => void) {
      this.dataHandler = handler
      return { dispose: vi.fn() }
    }

    dispose() {
      this.disposed = true
    }
  }

  class MockFitAddon {
    fit = vi.fn()

    constructor() {
      fitInstances.push(this)
    }
  }

  class MockEventSource {
    onmessage: ((event: MessageEvent<string>) => void) | null = null
    onerror: (() => void) | null = null
    closed = false
    listeners = new Map<string, (event: MessageEvent<string>) => void>()

    constructor(public readonly url: string) {
      eventSources.push(this)
    }

    addEventListener(type: string, listener: EventListener) {
      this.listeners.set(type, listener as (event: MessageEvent<string>) => void)
    }

    close() {
      this.closed = true
    }

    emitMessage(data: string) {
      this.onmessage?.(new MessageEvent('message', { data }))
    }

    emitExit(data: string) {
      this.listeners.get('exit')?.(new MessageEvent('exit', { data }))
    }

    emitError() {
      this.onerror?.()
    }
  }

  class MockResizeObserver {
    observed: Element | null = null

    constructor(private readonly callback: ResizeObserverCallback) {
      resizeObservers.push(this)
    }

    observe(element: Element) {
      this.observed = element
    }

    disconnect() {
      this.observed = null
    }

    fire() {
      this.callback([], this)
    }
  }

  return {
    MockTerminal,
    MockFitAddon,
    MockEventSource,
    MockResizeObserver,
    terminalInstances,
    fitInstances,
    eventSources,
    resizeObservers,
  }
})

vi.mock('xterm', () => ({
  Terminal: terminalMocks.MockTerminal,
}))

vi.mock('@xterm/addon-fit', () => ({
  FitAddon: terminalMocks.MockFitAddon,
}))

vi.mock('xterm/css/xterm.css', () => ({}))

const server: Server = {
  id: 'srv-1',
  name: 'bastion1',
  hostname: 'bastion1.yiucloud.com',
  ip_address: '10.10.1.10',
  os: 'Ubuntu 24.04',
  status: 'online',
  agent_version: 'v1.2.0',
  labels: '',
  last_seen_at: '',
  created_at: '',
  updated_at: '',
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve
    reject = promiseReject
  })
  return { promise, resolve, reject }
}

beforeEach(() => {
  mockApiFetch.mockReset()
  terminalMocks.terminalInstances.length = 0
  terminalMocks.fitInstances.length = 0
  terminalMocks.eventSources.length = 0
  terminalMocks.resizeObservers.length = 0
  vi.stubGlobal('EventSource', terminalMocks.MockEventSource)
  vi.stubGlobal('ResizeObserver', terminalMocks.MockResizeObserver)
  vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => {
    callback(0)
    return 1
  })
  vi.stubGlobal('cancelAnimationFrame', vi.fn())
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ServerTerminal', () => {
  it('shows the connecting state with host and shell fallbacks while a session is pending', async () => {
    const created = deferred<{ session_id: string }>()
    mockApiFetch.mockReturnValue(created.promise)

    render(<ServerTerminal serverId="srv-1" server={{ ...server, hostname: '', os: '' }} />)

    expect(await screen.findByText('Connecting')).toBeInTheDocument()
    expect(screen.getByText('10.10.1.10')).toBeInTheDocument()
    expect(screen.getByText(/Agent shell/)).toBeInTheDocument()
    expect(screen.getByText('pending...')).toBeInTheDocument()

    terminalMocks.terminalInstances[0].dataHandler?.('whoami\n')
    terminalMocks.resizeObservers[0].fire()
    expect(mockApiFetch).toHaveBeenCalledTimes(1)
  })

  it('falls back to the server name when host fields are unavailable', async () => {
    const created = deferred<{ session_id: string }>()
    mockApiFetch.mockReturnValue(created.promise)

    render(<ServerTerminal serverId="srv-1" server={{ ...server, hostname: '', ip_address: '' }} />)

    expect(await screen.findByText('Connecting')).toBeInTheDocument()
    expect(screen.getAllByText('bastion1').length).toBeGreaterThan(0)
  })

  it('opens a terminal session, streams output, sends input, resizes, and handles clean exit', async () => {
    mockApiFetch.mockResolvedValue({ session_id: 'sess-1' })

    render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ cols: 100, rows: 30 }),
    }))
    expect(terminalMocks.eventSources[0].url).toBe('/api/servers/srv-1/terminal/sessions/sess-1/stream')

    terminalMocks.eventSources[0].emitMessage(globalThis.btoa('ready\n'))
    expect(await screen.findByText('Connected')).toBeInTheDocument()
    expect(terminalMocks.terminalInstances[0].writes[0]).toBeInstanceOf(Uint8Array)

    terminalMocks.terminalInstances[0].dataHandler?.('whoami\n')
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions/sess-1/input', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ data: 'whoami\n' }),
      }))
    })

    terminalMocks.resizeObservers[0].fire()
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions/sess-1/resize', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ cols: 100, rows: 30 }),
      }))
    })
    expect(terminalMocks.fitInstances[0].fit).toHaveBeenCalled()

    terminalMocks.eventSources[0].emitExit(JSON.stringify({ exit_code: 0 }))
    expect(await screen.findByText('Closed')).toBeInTheDocument()
    expect(screen.getByText('Reconnect')).toBeInTheDocument()
    expect(terminalMocks.eventSources[0].closed).toBe(true)
    expect(terminalMocks.terminalInstances[0].writelnCalls).toContain('[session closed] Shell exited cleanly')

    terminalMocks.eventSources[0].emitError()
    expect(terminalMocks.terminalInstances[0].writelnCalls).not.toContain('[connection lost]')
  })

  it.each([
    ['invalid JSON', 'not-json', '[session closed] Shell exited'],
    ['null payload', 'null', '[session closed] Shell exited'],
    ['unknown exit', JSON.stringify({}), '[session closed] Shell exited with code unknown'],
    ['non-zero exit', JSON.stringify({ exit_code: 2 }), '[session closed] Shell exited with code 2'],
    ['exit error', JSON.stringify({ error: 'permission denied' }), '[session closed] permission denied'],
  ])('handles %s terminal exit payloads', async (_, payload, expectedLine) => {
    mockApiFetch.mockResolvedValue({ session_id: 'sess-exit' })

    render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    terminalMocks.eventSources[0].emitExit(payload)

    expect(await screen.findByText('Closed')).toBeInTheDocument()
    expect(terminalMocks.terminalInstances[0].writelnCalls).toContain(expectedLine)
  })

  it('handles non-message terminal exit events', async () => {
    mockApiFetch.mockResolvedValue({ session_id: 'sess-event' })

    render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    terminalMocks.eventSources[0].listeners.get('exit')?.(new Event('exit') as MessageEvent<string>)

    expect(await screen.findByText('Closed')).toBeInTheDocument()
    expect(terminalMocks.terminalInstances[0].writelnCalls).toContain('[session closed] Shell exited')
  })

  it('ignores terminal stream events after unmount', async () => {
    mockApiFetch.mockResolvedValue({ session_id: 'sess-cancelled-stream' })

    const { unmount } = render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    const stream = terminalMocks.eventSources[0]
    const term = terminalMocks.terminalInstances[0]
    unmount()

    stream.emitMessage(globalThis.btoa('late\n'))
    stream.emitExit(JSON.stringify({ exit_code: 0 }))
    stream.emitError()

    expect(term.writes).toHaveLength(0)
    expect(term.writelnCalls).not.toContain('[session closed] Shell exited cleanly')
    expect(term.writelnCalls).not.toContain('[connection lost]')
  })

  it('ignores transient input and resize failures', async () => {
    mockApiFetch.mockResolvedValueOnce({ session_id: 'sess-io' })

    render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })

    mockApiFetch.mockRejectedValueOnce(new Error('input failed'))
    terminalMocks.terminalInstances[0].dataHandler?.('id\n')
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions/sess-io/input', expect.objectContaining({
        method: 'POST',
      }))
    })

    mockApiFetch.mockRejectedValueOnce(new Error('resize failed'))
    terminalMocks.resizeObservers[0].fire()
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions/sess-io/resize', expect.objectContaining({
        method: 'POST',
      }))
    })
  })

  it('shows an error when session creation fails and can reconnect', async () => {
    mockApiFetch
      .mockRejectedValueOnce(new Error('terminal execution user not available'))
      .mockResolvedValueOnce({ session_id: 'sess-2' })

    render(<ServerTerminal serverId="srv-1" server={server} />)

    expect(await screen.findByText('Error')).toBeInTheDocument()
    expect(screen.getByText(/terminal execution user not available/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /reconnect/i }))

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    expect(terminalMocks.eventSources[0].url).toBe('/api/servers/srv-1/terminal/sessions/sess-2/stream')
  })

  it('shows the generic terminal error for non-error failures', async () => {
    mockApiFetch.mockRejectedValueOnce('failed')

    render(<ServerTerminal serverId="srv-1" server={server} />)

    expect(await screen.findByText('Error')).toBeInTheDocument()
    expect(screen.getByText(/unable to start terminal/i)).toBeInTheDocument()
    expect(terminalMocks.terminalInstances[0].writelnCalls).toContain('[error] Unable to start terminal')
  })

  it('marks the session as failed when the stream errors', async () => {
    mockApiFetch.mockResolvedValue({ session_id: 'sess-3' })

    render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    terminalMocks.eventSources[0].emitError()

    expect(await screen.findByText('Error')).toBeInTheDocument()
    expect(screen.getByText(/terminal connection lost/i)).toBeInTheDocument()
    expect(terminalMocks.terminalInstances[0].writelnCalls).toContain('[connection lost]')
  })

  it('closes an active session on unmount', async () => {
    mockApiFetch.mockResolvedValue({ session_id: 'sess-4' })

    const { unmount } = render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(terminalMocks.eventSources).toHaveLength(1)
    })
    unmount()

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions/sess-4', expect.objectContaining({
        method: 'DELETE',
      }))
    })
    expect(terminalMocks.eventSources[0].closed).toBe(true)
    expect(terminalMocks.terminalInstances[0].disposed).toBe(true)
  })

  it('closes a session that finishes opening after unmount', async () => {
    const created = deferred<{ session_id: string }>()
    mockApiFetch
      .mockReturnValueOnce(created.promise)
      .mockResolvedValueOnce({})

    const { unmount } = render(<ServerTerminal serverId="srv-1" server={server} />)

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions', expect.anything())
    })
    unmount()

    await act(async () => {
      created.resolve({ session_id: 'sess-late' })
      await created.promise
    })

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/servers/srv-1/terminal/sessions/sess-late', expect.objectContaining({
        method: 'DELETE',
      }))
    })
  })
})

describe('OfflineTerminalState', () => {
  it('renders the offline terminal message', () => {
    render(<OfflineTerminalState server={{ ...server, status: 'offline' }} />)

    expect(screen.getByText('Terminal')).toBeInTheDocument()
    expect(screen.getByText('Awaiting agent')).toBeInTheDocument()
    expect(screen.getByText(/terminal access is only available/i)).toBeInTheDocument()
    expect(screen.getByText(/bastion1/)).toBeInTheDocument()
  })
})
