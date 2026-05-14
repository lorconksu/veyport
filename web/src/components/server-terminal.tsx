import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle, Loader2, RotateCcw, Terminal } from 'lucide-react'
import { FitAddon } from '@xterm/addon-fit'
import { Terminal as XTerm } from 'xterm'
import 'xterm/css/xterm.css'

import { apiFetch } from '@/lib/api'
import type { Server, TerminalSessionResponse } from '@/types/api'

type TerminalStatus = 'connecting' | 'connected' | 'closed' | 'error'

interface TerminalExitPayload {
  exit_code?: number
  error?: string
}

function decodeBase64Chunk(encoded: string): Uint8Array {
  const binary = globalThis.atob(encoded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.codePointAt(i) ?? 0
  }
  return bytes
}

function statusLabel(status: TerminalStatus): string {
  switch (status) {
    case 'connected':
      return 'Connected'
    case 'closed':
      return 'Closed'
    case 'error':
      return 'Error'
    default:
      return 'Connecting'
  }
}

function statusClass(status: TerminalStatus): string {
  switch (status) {
    case 'connected':
      return 'border border-[#79e2ac]/25 bg-[#79e2ac]/10 text-[#79e2ac]'
    case 'closed':
      return 'border border-white/10 bg-white/10 text-[#d5ddd8]'
    case 'error':
      return 'border border-[#ff9b8a]/25 bg-[#ff9b8a]/10 text-[#ffb2a5]'
    default:
      return 'border border-[#8fc6ff]/25 bg-[#8fc6ff]/10 text-[#8fc6ff]'
  }
}

function parseTerminalExitPayload(event: Event): TerminalExitPayload {
  if (!(event instanceof MessageEvent) || typeof event.data !== 'string') {
    return { error: 'Shell exited' }
  }
  try {
    const payload: unknown = JSON.parse(event.data)
    return typeof payload === 'object' && payload !== null ? payload : { error: 'Shell exited' }
  } catch {
    return { error: 'Shell exited' }
  }
}

function TerminalStatusIcon({ status }: Readonly<{ status: TerminalStatus }>) {
  switch (status) {
    case 'connected':
      return <CheckCircle className="w-3.5 h-3.5" />
    case 'connecting':
      return <Loader2 className="w-3.5 h-3.5 animate-spin" />
    default:
      return <AlertTriangle className="w-3.5 h-3.5" />
  }
}

export function ServerTerminal({
  serverId,
  server,
}: Readonly<{
  serverId: string
  server: Server
}>) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const terminalRef = useRef<XTerm | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const resizeObserverRef = useRef<ResizeObserver | null>(null)
  const dataDisposableRef = useRef<{ dispose: () => void } | null>(null)
  const streamRef = useRef<EventSource | null>(null)
  const sessionIdRef = useRef<string | null>(null)
  const cleanupInFlightRef = useRef(false)
  const statusRef = useRef<TerminalStatus>('connecting')
  const animationFrameRef = useRef<number | null>(null)
  const terminalReadyRef = useRef(false)

  const [status, setStatus] = useState<TerminalStatus>('connecting')
  const [statusMessage, setStatusMessage] = useState('Negotiating PTY session...')
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [restartNonce, setRestartNonce] = useState(0)
  const [terminalReady, setTerminalReady] = useState(false)

  const hostLabel = useMemo(
    () => server.hostname || server.ip_address || server.name,
    [server.hostname, server.ip_address, server.name],
  )

  const setTerminalStatus = useCallback((nextStatus: TerminalStatus, message: string) => {
    statusRef.current = nextStatus
    setStatus(nextStatus)
    setStatusMessage(message)
  }, [])

  const setTerminalReadyState = useCallback((ready: boolean) => {
    terminalReadyRef.current = ready
    setTerminalReady(ready)
  }, [])

  const restartTerminal = useCallback(() => {
    setTerminalStatus('connecting', 'Negotiating PTY session...')
    setRestartNonce((value) => value + 1)
  }, [setTerminalStatus])

  const createTerminal = useCallback(() => {
    const term = new XTerm({
      convertEol: true,
      cursorBlink: true,
      cursorStyle: 'bar',
      fontFamily: '"MesloLGLDZ Nerd Font Mono", "IBM Plex Mono", "SFMono-Regular", ui-monospace, monospace',
      fontSize: 14,
      theme: {
        background: '#071019',
        foreground: '#d9f7e8',
        cursor: '#79e2ac',
        cursorAccent: '#071019',
        selectionBackground: 'rgba(121, 226, 172, 0.25)',
        black: '#071019',
        red: '#ff8a7a',
        green: '#79e2ac',
        yellow: '#f4b56a',
        blue: '#7bb8ff',
        magenta: '#df9cff',
        cyan: '#79dbe8',
        white: '#d9f7e8',
        brightBlack: '#5c6873',
        brightRed: '#ffb2a5',
        brightGreen: '#b8f3cf',
        brightYellow: '#ffd29a',
        brightBlue: '#afd7ff',
        brightMagenta: '#efc8ff',
        brightCyan: '#b8f4fa',
        brightWhite: '#ffffff',
      },
    })
    const fitAddon = new FitAddon()
    term.loadAddon(fitAddon)
    terminalRef.current = term
    fitAddonRef.current = fitAddon

    dataDisposableRef.current = term.onData((data) => {
      const activeSession = sessionIdRef.current
      if (!activeSession) return
      void apiFetch(`/servers/${serverId}/terminal/sessions/${activeSession}/input`, {
        method: 'POST',
        body: JSON.stringify({ data }),
      }).catch(() => {
        // The stream handler will surface disconnections; avoid spamming per keystroke.
      })
    })

    return { term, fitAddon }
  }, [serverId])

  const closeSession = useCallback(async () => {
    if (cleanupInFlightRef.current) {
      return
    }
    cleanupInFlightRef.current = true

    const activeStream = streamRef.current
    streamRef.current = null
    activeStream?.close()

    const activeSession = sessionIdRef.current
    sessionIdRef.current = null
    setSessionId(null)

    if (activeSession) {
      await apiFetch(`/servers/${serverId}/terminal/sessions/${activeSession}`, {
        method: 'DELETE',
      }).catch(() => {
        // Session may already be closed on the agent side; ignore cleanup races.
      })
    }

    cleanupInFlightRef.current = false
  }, [serverId])

  const sendResize = useCallback(() => {
    const term = terminalRef.current
    const fitAddon = fitAddonRef.current
    const activeSession = sessionIdRef.current
    const container = containerRef.current
    if (!term || !fitAddon || !container) {
      return
    }
    if (!terminalReadyRef.current) {
      return
    }
    fitAddon.fit()
    if (!activeSession) {
      return
    }
    void apiFetch(`/servers/${serverId}/terminal/sessions/${activeSession}/resize`, {
      method: 'POST',
      body: JSON.stringify({ cols: term.cols, rows: term.rows }),
    }).catch(() => {
      // Ignore transient resize failures; the stream state will surface hard failures.
    })
  }, [serverId])

  useLayoutEffect(() => {
    const container = containerRef.current
    if (!container) {
      return
    }

    const { term, fitAddon } = createTerminal()
    term.open(container)
    terminalReadyRef.current = false

    animationFrameRef.current = globalThis.requestAnimationFrame(() => {
      fitAddon.fit()
      term.focus()
      setTerminalReadyState(true)
      animationFrameRef.current = null
    })

    const observer = new ResizeObserver(() => {
      globalThis.requestAnimationFrame(() => {
        sendResize()
      })
    })
    observer.observe(container)
    resizeObserverRef.current = observer

    return () => {
      observer.disconnect()
      resizeObserverRef.current = null
      if (animationFrameRef.current !== null) {
        globalThis.cancelAnimationFrame(animationFrameRef.current)
        animationFrameRef.current = null
      }
      dataDisposableRef.current?.dispose()
      dataDisposableRef.current = null
      terminalRef.current?.dispose()
      terminalRef.current = null
      fitAddonRef.current = null
      setTerminalReadyState(false)
    }
  }, [createTerminal, sendResize, setTerminalReadyState])

  useEffect(() => {
    if (!terminalReady) {
      return
    }

    let cancelled = false
    const termInstance = terminalRef.current
    const fitAddonInstance = fitAddonRef.current
    if (!termInstance || !fitAddonInstance) {
      return
    }
    const activeTerm = termInstance
    const activeFitAddon = fitAddonInstance

    activeTerm.reset()
    activeFitAddon.fit()
    activeTerm.focus()
    activeTerm.writeln(`Connecting to ${server.name}...`)

    async function start() {
      try {
        const created = await apiFetch<TerminalSessionResponse>(`/servers/${serverId}/terminal/sessions`, {
          method: 'POST',
          body: JSON.stringify({
            cols: activeTerm.cols,
            rows: activeTerm.rows,
          }),
        })

        if (cancelled) {
          await apiFetch(`/servers/${serverId}/terminal/sessions/${created.session_id}`, {
            method: 'DELETE',
          }).catch(() => {})
          return
        }

        sessionIdRef.current = created.session_id
        setSessionId(created.session_id)

        const stream = new EventSource(`/api/servers/${serverId}/terminal/sessions/${created.session_id}/stream`)
        streamRef.current = stream

        stream.onmessage = (event) => {
          if (cancelled) return
          setTerminalStatus('connected', 'Live shell ready')
          activeTerm.write(decodeBase64Chunk(event.data))
        }

        stream.addEventListener('exit', (event) => {
          if (cancelled) return
          const payload = parseTerminalExitPayload(event)
          stream.close()
          streamRef.current = null
          sessionIdRef.current = null
          setSessionId(null)
          const message = payload.error || (payload.exit_code === 0 ? 'Shell exited cleanly' : `Shell exited with code ${payload.exit_code ?? 'unknown'}`)
          setTerminalStatus('closed', message)
          activeTerm.writeln('')
          activeTerm.writeln(`[session closed] ${message}`)
        })

        stream.onerror = () => {
          if (cancelled) return
          stream.close()
          streamRef.current = null
          sessionIdRef.current = null
          setSessionId(null)
          if (statusRef.current === 'closed') {
            return
          }
          setTerminalStatus('error', 'Terminal connection lost')
          activeTerm.writeln('')
          activeTerm.writeln('[connection lost]')
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unable to start terminal'
        if (cancelled) return
        setTerminalStatus('error', message)
        activeTerm.writeln('')
        activeTerm.writeln(`[error] ${message}`)
      }
    }

    start().catch(() => undefined)

    return () => {
      cancelled = true
      closeSession().catch(() => undefined)
    }
  }, [closeSession, restartNonce, server.name, serverId, setTerminalStatus, terminalReady])

  useEffect(() => {
    return () => {
      resizeObserverRef.current?.disconnect()
      if (animationFrameRef.current !== null) {
        globalThis.cancelAnimationFrame(animationFrameRef.current)
      }
      streamRef.current?.close()
    }
  }, [])

  return (
    <div className="flex-1 min-h-0 bg-[#071019] text-[#d9f7e8] flex flex-col">
      <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-white/10 bg-black/20 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-status-error/90" />
            <span className="w-2.5 h-2.5 rounded-full bg-status-warning/90" />
            <span className="w-2.5 h-2.5 rounded-full bg-status-ok/90" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#79e2ac]" />
              <p className="text-sm font-medium text-white">Live Terminal</p>
            </div>
            <p className="text-xs text-[#8eb7a4] truncate">
              {server.name} · {server.os || 'Agent shell'} · {statusMessage}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 ${statusClass(status)}`}>
            <TerminalStatusIcon status={status} />
            {statusLabel(status)}
          </span>
          {(status === 'closed' || status === 'error') && (
            <button
              type="button"
              onClick={restartTerminal}
              className="inline-flex items-center gap-1 rounded-full border border-white/10 px-2 py-1 text-[#d5ddd8] hover:bg-white/10 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reconnect
            </button>
          )}
        </div>
      </div>

      <div className="px-4 py-3 border-b border-white/8 bg-[#08141d] shrink-0">
        <div className="grid gap-2 md:grid-cols-3">
          <div className="rounded-lg border border-white/8 bg-white/5 px-3 py-2">
            <p className="text-[11px] uppercase tracking-[0.18em] text-[#7aa291]">Host</p>
            <p className="mt-1 font-mono text-sm text-white truncate">{hostLabel}</p>
          </div>
          <div className="rounded-lg border border-white/8 bg-white/5 px-3 py-2">
            <p className="text-[11px] uppercase tracking-[0.18em] text-[#7aa291]">Session</p>
            <p className="mt-1 font-mono text-sm text-white truncate">{sessionId ? `shell://${sessionId.slice(0, 12)}` : 'pending...'}</p>
          </div>
          <div className="rounded-lg border border-white/8 bg-white/5 px-3 py-2">
            <p className="text-[11px] uppercase tracking-[0.18em] text-[#7aa291]">Access</p>
            <p className="mt-1 text-sm text-white">Shell over the agent stream</p>
          </div>
        </div>
      </div>

      <div className="flex-1 min-h-0 px-4 py-4">
        <div
          ref={containerRef}
          className="h-full w-full rounded-2xl border border-white/8 bg-[#071019] px-2 py-2 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
        />
      </div>
    </div>
  )
}

export function OfflineTerminalState({ server }: Readonly<{ server: Server }>) {
  return (
    <div className="flex-1 min-h-0 bg-[#071019] text-[#d9f7e8] flex flex-col">
      <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-white/10 bg-black/20 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-status-error/90" />
            <span className="w-2.5 h-2.5 rounded-full bg-status-warning/90" />
            <span className="w-2.5 h-2.5 rounded-full bg-status-ok/90" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#f4b56a]" />
              <p className="text-sm font-medium text-white">Terminal</p>
            </div>
            <p className="text-xs text-[#8eb7a4] truncate">
              {server.name} · waiting for the agent to come online
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="inline-flex items-center gap-1 rounded-full border border-[#f4b56a]/25 bg-[#f4b56a]/10 px-2 py-1 text-[#f4b56a]">
            <AlertTriangle className="w-3.5 h-3.5" />
            Awaiting agent
          </span>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center px-6">
        <div className="max-w-lg rounded-2xl border border-white/8 bg-white/5 px-6 py-8 text-center">
          <p className="text-sm font-medium text-white">Terminal access is only available when the node is online</p>
          <p className="mt-2 text-sm text-[#9db5a8]">
            Reconnect the agent, then reopen this tab to start a live shell session. The terminal shares the same secure agent stream as file browsing and log tailing.
          </p>
        </div>
      </div>
    </div>
  )
}
