import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X, Copy, Check, Loader2, CheckCircle2 } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import type { CreateServerRequest, CreateServerResponse, Server } from '@/types/api'

interface AddServerModalProps {
  onClose: () => void
}

const TIMEOUT_MS = 2 * 60 * 1000 // 2 minutes

export function AddServerModal({ onClose }: Readonly<AddServerModalProps>) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [result, setResult] = useState<CreateServerResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [timedOut, setTimedOut] = useState(false)

  const createMutation = useMutation({
    mutationFn: (req: CreateServerRequest) =>
      apiFetch<CreateServerResponse>('/servers', {
        method: 'POST',
        body: JSON.stringify(req),
      }),
    onSuccess: (data) => {
      setResult(data)
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    },
  })

  // Poll server status after creation
  const { data: serverStatus } = useQuery({
    queryKey: ['server-status', result?.server.id],
    queryFn: () => apiFetch<Server>(`/servers/${result!.server.id}`),
    enabled: !!result && !timedOut,
    refetchInterval: 3000,
  })

  const isOnline = serverStatus?.status === 'online'

  // Timeout after 2 minutes
  useEffect(() => {
    if (!result || isOnline) return
    const timer = setTimeout(() => setTimedOut(true), TIMEOUT_MS)
    return () => clearTimeout(timer)
  }, [result, isOnline])

  // Invalidate server list when agent comes online
  useEffect(() => {
    if (isOnline) {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    }
  }, [isOnline, queryClient])

  const handleGenerate = () => {
    if (!name.trim()) return
    createMutation.mutate({ name: name.trim() })
  }

  const handleCopy = async () => {
    if (!result) return
    await navigator.clipboard.writeText(result.install_command)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const canClose = !result || isOnline || timedOut

  function renderAgentStatus() {
    if (isOnline) {
      return (
        <>
          <CheckCircle2 className="w-4 h-4 text-status-online" />
          <span className="text-status-online">Agent connected!</span>
        </>
      )
    }
    if (timedOut) {
      return (
        <p className="text-status-warning text-xs">
          Agent hasn&apos;t connected yet. Check the install command output for errors.
        </p>
      )
    }
    return (
      <>
        <Loader2 className="w-4 h-4 text-text-muted animate-spin" />
        <span className="text-text-muted">Waiting for agent to connect...</span>
      </>
    )
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-surface border border-border rounded-lg w-full max-w-lg mx-4 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-text-primary font-semibold">Add Server</h3>
          <button
            type="button"
            onClick={onClose}
            disabled={!canClose}
            className="text-text-muted hover:text-text-primary disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {result ? (
          /* Step 2: Show install command + wait for agent */
          <div>
            <p className="text-sm text-text-secondary mb-3">
              Run this command on <span className="text-text-primary font-medium">{result.server.name}</span> to install the agent:
            </p>
            <div className="relative">
              <pre className="bg-base border border-border rounded p-3 text-xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap break-all">
                {result.install_command}
              </pre>
              <button
                type="button"
                onClick={handleCopy}
                className="absolute top-2 right-2 p-1 bg-elevated border border-border rounded text-text-muted hover:text-text-primary transition-colors"
                title="Copy to clipboard"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-status-online" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <p className="text-xs text-status-warning mt-2">
              Expires in 1 hour. Token is shown only once.
            </p>

            {/* Status indicator */}
            <div className="mt-4 flex items-center gap-2 text-sm">
              {renderAgentStatus()}
            </div>

            <div className="flex justify-end mt-4">
              <button
                type="button"
                onClick={onClose}
                disabled={!canClose}
                className="px-4 py-2 bg-elevated hover:bg-border disabled:opacity-30 disabled:cursor-not-allowed text-text-primary text-sm rounded transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        ) : (
          /* Step 1: Enter name */
          <div>
            <label htmlFor="server-name" className="block text-sm text-text-secondary mb-1">Server Name</label>
            <input
              id="server-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleGenerate()}
              placeholder="e.g., web-prod-1"
              className="w-full px-3 py-2 bg-elevated border border-border rounded text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
              autoFocus
            />
            {createMutation.isError && (
              <p className="text-status-error text-xs mt-2">
                {createMutation.error?.message || 'Failed to create server'}
              </p>
            )}
            <div className="flex justify-end mt-4">
              <button
                type="button"
                onClick={handleGenerate}
                disabled={!name.trim() || createMutation.isPending}
                className="px-4 py-2 bg-accent hover:bg-accent-hover disabled:opacity-50 text-white text-sm rounded transition-colors"
              >
                {createMutation.isPending ? 'Generating...' : 'Generate'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
