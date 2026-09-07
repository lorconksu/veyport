import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, Trash2, X, Search, Terminal } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { relativeTime } from '@/lib/time'
import { statusDot } from '@/lib/server-utils'
import { useAuth } from '@/hooks/use-auth'
import { AddServerModal } from '@/pages/add-server-modal'
import { InstallCliModal } from '@/pages/install-cli-modal'
import { useAllServers } from '@/hooks/use-servers'
import type { ServerListResponse } from '@/types/api'

/** Run async tasks with bounded concurrency. */
async function parallelLimit<T>(
  tasks: (() => Promise<T>)[],
  limit: number,
): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = new Array(tasks.length)
  let nextIndex = 0

  async function runNext() {
    while (nextIndex < tasks.length) {
      const i = nextIndex++
      try {
        const value = await tasks[i]()
        results[i] = { status: 'fulfilled', value }
      } catch (reason) {
        results[i] = { status: 'rejected', reason }
      }
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => runNext())
  await Promise.all(workers)
  return results
}

export function DashboardPage() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const isAdmin = user?.role === 'admin'

  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [searchTerm, setSearchTerm] = useState('')
  const [debouncedSearchTerm, setDebouncedSearchTerm] = useState('')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showAddModal, setShowAddModal] = useState(false)
  const [showInstallCliModal, setShowInstallCliModal] = useState(false)

  // Debounce search term by 300ms to avoid API call on every keystroke
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearchTerm(searchTerm), 300)
    return () => clearTimeout(timer)
  }, [searchTerm])

  const hasFilters = !!statusFilter || !!debouncedSearchTerm

  // Use shared query when unfiltered; separate query when filters are active
  const allServersQuery = useAllServers()

  const filteredQuery = useQuery({
    queryKey: ['servers', 'filtered', statusFilter, debouncedSearchTerm],
    queryFn: () => {
      const params = new URLSearchParams()
      if (statusFilter) params.set('status', statusFilter)
      if (debouncedSearchTerm) params.set('search', debouncedSearchTerm)
      return apiFetch<ServerListResponse>(`/servers?${params.toString()}`)
    },
    refetchInterval: 10_000,
    enabled: hasFilters,
  })

  const data = hasFilters ? filteredQuery.data : allServersQuery.data
  const isLoading = hasFilters ? filteredQuery.isLoading : allServersQuery.isLoading

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/servers/${id}/unregister`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['servers'] }),
  })

  const batchDeleteMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const tasks = ids.map((id) => () =>
        apiFetch(`/servers/${id}/unregister`, { method: 'DELETE' }),
      )
      const results = await parallelLimit(tasks, 5)
      const failures = results.filter((r) => r.status === 'rejected')
      if (failures.length > 0 && failures.length === ids.length) {
        throw new Error('All unregister requests failed')
      }
    },
    onSuccess: () => {
      setSelectedIds(new Set())
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    },
    onError: () => {
      // Even on partial failure, clear selection and refresh the list
      setSelectedIds(new Set())
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    },
  })

  const servers = data?.servers ?? []
  const total = data?.total ?? 0

  const allSelected = servers.length > 0 && servers.every((s) => selectedIds.has(s.id))

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(servers.map((s) => s.id)))
    }
  }

  const statusFilters: { label: string; value: string | undefined }[] = [
    { label: 'All', value: undefined },
    { label: 'Online', value: 'online' },
    { label: 'Offline', value: 'offline' },
    { label: 'Pending', value: 'pending' },
  ]

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">Fleet Dashboard</h2>
          <p className="text-text-muted text-sm">{total} server{total === 1 ? '' : 's'}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowInstallCliModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-elevated hover:bg-border text-text-primary text-sm rounded transition-colors"
          >
            <Terminal className="w-4 h-4" />
            Install CLI
          </button>
          {isAdmin && (
            <button
              type="button"
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm rounded transition-colors"
            >
              <Plus className="w-4 h-4" />
              Add Server
            </button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex gap-1">
          {statusFilters.map(({ label, value }) => (
            <button
              key={label}
              type="button"
              onClick={() => setStatusFilter(value)}
              className={`px-3 py-1 text-xs rounded transition-colors ${
                statusFilter === value
                  ? 'bg-accent text-white'
                  : 'bg-elevated text-text-muted hover:text-text-secondary'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-faint" />
          <input
            type="text"
            placeholder="Search servers..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-elevated border border-border rounded text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
        </div>
      </div>

      {/* Mass action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 mb-4 px-3 py-2 bg-elevated border border-border rounded text-sm">
          <span className="text-text-secondary">{selectedIds.size} selected</span>
          <button
            type="button"
            onClick={() => batchDeleteMutation.mutate([...selectedIds])}
            disabled={batchDeleteMutation.isPending}
            className="flex items-center gap-1 px-2 py-1 text-status-offline hover:bg-surface rounded transition-colors text-xs"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Unregister Selected
          </button>
          <button
            type="button"
            onClick={() => setSelectedIds(new Set())}
            className="flex items-center gap-1 px-2 py-1 text-text-muted hover:text-text-secondary text-xs"
          >
            <X className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>
      )}

      {/* Table */}
      {isLoading && (
        <div className="text-text-muted text-sm py-8 text-center">Loading servers...</div>
      )}
      {!isLoading && servers.length === 0 && (
        <div className="text-text-muted text-sm py-8 text-center">
          No servers found.{' '}
          {isAdmin && (
            <button type="button" onClick={() => setShowAddModal(true)} className="text-accent hover:underline">
              Add your first server
            </button>
          )}
        </div>
      )}
      {!isLoading && servers.length > 0 && (
        <div className="border border-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-elevated text-text-muted text-xs uppercase tracking-wider">
                {isAdmin && (
                  <th className="px-3 py-2 w-8">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleSelectAll}
                      className="rounded"
                    />
                  </th>
                )}
                <th className="px-3 py-2 w-8">Status</th>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Hostname / IP</th>
                <th className="px-3 py-2 text-left">OS</th>
                <th className="px-3 py-2 text-left">Last Seen</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {servers.map((srv) => (
                <tr key={srv.id} className="hover:bg-elevated/50 transition-colors">
                  {isAdmin && (
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(srv.id)}
                        onChange={() => toggleSelect(srv.id)}
                        className="rounded"
                      />
                    </td>
                  )}
                  <td className="px-3 py-2 text-center">
                    <span className={statusDot[srv.status]}>●</span>
                  </td>
                  <td className="px-3 py-2">
                    <Link
                      to={`/servers/${srv.id}`}
                      className="text-text-primary hover:text-accent transition-colors"
                    >
                      {srv.name}
                    </Link>
                  </td>
                  <td className="px-3 py-2 font-mono text-text-secondary text-xs">
                    {srv.hostname || srv.ip_address ? `${srv.hostname ?? '—'} / ${srv.ip_address ?? '—'}` : '—'}
                  </td>
                  <td className="px-3 py-2 text-text-secondary">{srv.os ?? '—'}</td>
                  <td className="px-3 py-2 text-text-muted">
                    {srv.status === 'pending' ? (
                      <span className="text-status-warning">Pending agent</span>
                    ) : (
                      relativeTime(srv.last_seen_at)
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {isAdmin && (
                      <button
                        type="button"
                        onClick={() => deleteMutation.mutate(srv.id)}
                        disabled={deleteMutation.isPending}
                        className="text-text-muted hover:text-status-offline transition-colors text-xs"
                      >
                        Unregister
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add Server Modal */}
      {showAddModal && <AddServerModal onClose={() => setShowAddModal(false)} />}

      {/* Install CLI Modal */}
      {showInstallCliModal && <InstallCliModal onClose={() => setShowInstallCliModal(false)} />}
    </div>
  )
}
