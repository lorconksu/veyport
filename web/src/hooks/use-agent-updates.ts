import { useEffect, useId, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '@/lib/api'
import { checkAgentUpdate } from '@/lib/agent-updates-api'
import { hasCapability } from '@/lib/auth'
import { securityIdentityKey } from '@/lib/security-authority'
import { useAuth } from './use-auth'
import type { Server } from '@/types/api'
import type { User } from '@/types/api'
import type { AgentUpdateCheck } from '@/types/agent-updates'

export const AGENT_UPDATE_PAGE_SIZE = 25
export interface AgentUpdateAvailability { check?: AgentUpdateCheck; error?: Error }

export function agentUpdateIdentityKey(user: User | null): string {
  return JSON.stringify([securityIdentityKey(user), user?.role, hasCapability(user, 'operations.admin')])
}

export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(document.visibilityState !== 'hidden')
  useEffect(() => {
    const changed = () => setVisible(document.visibilityState !== 'hidden')
    document.addEventListener('visibilitychange', changed)
    return () => document.removeEventListener('visibilitychange', changed)
  }, [])
  return visible
}

// Availability is limited to the displayed page, with three workers and no
// hidden-tab polling. Queued work is cancelled on a page or authority change.
export function useAgentUpdates(servers: Server[]) {
  const { user, refreshUser } = useAuth()
  const instance = useId()
  const scope = `agent-updates:${instance}:${agentUpdateIdentityKey(user)}`
  const isAdmin = hasCapability(user, 'operations.admin')
  const visible = usePageVisible()
  const client = useQueryClient()
  const nodes = servers.slice(0, AGENT_UPDATE_PAGE_SIZE).filter(server => server.status === 'online')

  useEffect(() => () => {
    void client.cancelQueries({ queryKey: [scope] })
    client.removeQueries({ queryKey: [scope] })
  }, [client, scope])
  useEffect(() => {
    if (!visible || !isAdmin) void client.cancelQueries({ queryKey: [scope, 'availability'] })
  }, [client, scope, visible, isAdmin])

  const availability = useQuery({
    queryKey: [scope, 'availability', nodes.map(node => node.id)],
    enabled: isAdmin && visible && nodes.length > 0,
    staleTime: 30_000,
    refetchInterval: visible ? 60_000 : false,
    retry: false,
    queryFn: async ({ signal }) => {
      const results: Record<string, AgentUpdateAvailability> = {}
      const denied = new AbortController()
      const requestSignal = AbortSignal.any([signal, denied.signal])
      let next = 0
      let denial: Error | undefined
      const worker = async () => {
        while (next < nodes.length && !requestSignal.aborted) {
          const node = nodes[next++]
          try {
            results[node.id] = { check: await checkAgentUpdate(node.id, requestSignal) }
          } catch (error) {
            results[node.id] = { error: error instanceof Error ? error : new Error('Update check failed') }
            if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
              denial = error
              denied.abort()
              void refreshUser()
            }
          }
        }
      }
      await Promise.all(Array.from({ length: Math.min(3, nodes.length) }, worker))
      signal.throwIfAborted()
      if (denial) for (const node of nodes) results[node.id] ??= { error: denial }
      return results
    },
  })
  return { scope, availability: availability.data ?? {}, isAdmin }
}
