import { useState, useMemo, useCallback, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Info, Save, ShieldAlert } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import type {
  AuditCatalogResponse,
  AuditDetectionsResponse,
  AuditExportResponse,
  AuditExportHistoryResponse,
  AuditFlagsResponse,
  AuditHealth,
  AuditLogResponse,
  AuditRetentionRunResponse,
  AuditReviewsResponse,
  AuditSavedFiltersResponse,
  AuditSettings,
  User,
} from '@/types/api'

const PAGE_SIZE = 50

export function AuditLogsPage() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [filters, setFilters] = useState<{
    action: string
    userId: string
    outcome: string
    from: string
    to: string
  }>({ action: '', userId: '', outcome: '', from: '', to: '' })
  const [offset, setOffset] = useState(0)
  const [savedFilterName, setSavedFilterName] = useState('')
  const [reviewNotes, setReviewNotes] = useState('')
  const [settingsForm, setSettingsForm] = useState<AuditSettings | null>(null)

  const buildParams = () => {
    const params = new URLSearchParams()
    params.set('limit', String(PAGE_SIZE))
    params.set('offset', String(offset))
    if (filters.action) params.set('action', filters.action)
    if (filters.userId) params.set('user_id', filters.userId)
    if (filters.outcome) params.set('outcome', filters.outcome)
    if (filters.from) params.set('from', new Date(filters.from).toISOString())
    if (filters.to) params.set('to', new Date(filters.to + 'T23:59:59').toISOString())
    return params.toString()
  }

  const serialisedFilters = JSON.stringify(filters)

  const { data, isLoading } = useQuery({
    queryKey: ['audit-logs', filters, offset],
    queryFn: async () => (await apiFetch<AuditLogResponse>(`/audit-logs?${buildParams()}`)) ?? { entries: [], total: 0, limit: PAGE_SIZE, offset },
  })

  const { data: usersData } = useQuery({
    queryKey: ['audit-users'],
    queryFn: async () => (await apiFetch<{ users: User[] }>('/audit-users')) ?? { users: [] },
  })
  const { data: health } = useQuery({
    queryKey: ['audit-health'],
    queryFn: async () => (await apiFetch<AuditHealth>('/audit-logs/health')) ?? { degraded: false, failure_count: 0 },
  })
  const { data: settings } = useQuery({
    queryKey: ['audit-settings'],
    queryFn: async () => (await apiFetch<AuditSettings>('/audit-logs/settings')) ?? {
      retention_days: 90,
      review_reminder_days: 7,
      thresholds: {
        login_failures_per_hour: 10,
        registration_failures_per_hour: 5,
      },
    },
  })
  const { data: catalog } = useQuery({
    queryKey: ['audit-catalog'],
    queryFn: async () => (await apiFetch<AuditCatalogResponse>('/audit-logs/catalog')) ?? { entries: [], last_updated_at: '' },
  })
  const { data: detections } = useQuery({
    queryKey: ['audit-detections'],
    queryFn: async () => (await apiFetch<AuditDetectionsResponse>('/audit-logs/detections')) ?? { detections: [] },
    refetchInterval: 60_000,
  })
  const { data: reviews } = useQuery({
    queryKey: ['audit-reviews'],
    queryFn: async () => (await apiFetch<AuditReviewsResponse>('/audit-logs/reviews?limit=5')) ?? { reviews: [] },
  })
  const { data: savedFilters } = useQuery({
    queryKey: ['audit-saved-filters'],
    queryFn: async () => (await apiFetch<AuditSavedFiltersResponse>('/audit-logs/filters')) ?? { filters: [] },
  })
  const { data: exportHistory } = useQuery({
    queryKey: ['audit-export-history'],
    queryFn: async () => (await apiFetch<AuditExportHistoryResponse>('/audit-logs/exports')) ?? { entries: [] },
  })
  const { data: flags } = useQuery({
    queryKey: ['audit-flags'],
    queryFn: async () => (await apiFetch<AuditFlagsResponse>('/audit-logs/flags')) ?? { flags: [] },
  })

  useEffect(() => {
    if (settings) {
      setSettingsForm(settings)
    }
  }, [settings])

  const exportMutation = useMutation({
    mutationFn: () => apiFetch<AuditExportResponse>(`/audit-logs/export?${buildParams()}`),
    onSuccess: (resp) => {
      const blob = new Blob([JSON.stringify(resp, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `aerodocs-audit-export-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] })
      queryClient.invalidateQueries({ queryKey: ['audit-export-history'] })
    },
  })

  const settingsMutation = useMutation({
    mutationFn: (nextSettings: AuditSettings) =>
      apiFetch<AuditSettings>('/audit-logs/settings', {
        method: 'PUT',
        body: JSON.stringify(nextSettings),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-settings'] })
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] })
      queryClient.invalidateQueries({ queryKey: ['audit-detections'] })
    },
  })

  const retentionMutation = useMutation({
    mutationFn: () => apiFetch<AuditRetentionRunResponse>('/audit-logs/retention/run', { method: 'POST' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] })
      queryClient.invalidateQueries({ queryKey: ['audit-health'] })
      queryClient.invalidateQueries({ queryKey: ['audit-export-history'] })
    },
  })

  const saveFilterMutation = useMutation({
    mutationFn: () =>
      apiFetch('/audit-logs/filters', {
        method: 'POST',
        body: JSON.stringify({ name: savedFilterName, filters_json: serialisedFilters }),
      }),
    onSuccess: () => {
      setSavedFilterName('')
      queryClient.invalidateQueries({ queryKey: ['audit-saved-filters'] })
    },
  })

  const deleteFilterMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/audit-logs/filters/${id}`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['audit-saved-filters'] }),
  })

  const reviewMutation = useMutation({
    mutationFn: () =>
      apiFetch('/audit-logs/reviews', {
        method: 'POST',
        body: JSON.stringify({
          filters_json: serialisedFilters,
          notes: reviewNotes,
          from: filters.from ? new Date(filters.from).toISOString() : null,
          to: filters.to ? new Date(filters.to + 'T23:59:59').toISOString() : null,
        }),
      }),
    onSuccess: () => {
      setReviewNotes('')
      queryClient.invalidateQueries({ queryKey: ['audit-reviews'] })
      queryClient.invalidateQueries({ queryKey: ['audit-detections'] })
    },
  })

  const flagMutation = useMutation({
    mutationFn: ({ entryId, note }: { entryId: string | null, note: string }) =>
      apiFetch('/audit-logs/flags', {
        method: 'POST',
        body: JSON.stringify({
          entry_id: entryId,
          filters_json: serialisedFilters,
          note,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-flags'] })
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })

  const users = usersData?.users ?? []
  const hasActiveFilters = filters.action || filters.userId || filters.outcome || filters.from || filters.to

  const clearFilters = () => {
    setFilters({ action: '', userId: '', outcome: '', from: '', to: '' })
    setOffset(0)
  }

  const updateFilter = (key: keyof typeof filters, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }))
    setOffset(0)
  }

  const formatDate = (iso: string) => {
    return new Date(iso).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: 'numeric', minute: '2-digit',
    })
  }

  const userMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const u of users) {
      map.set(u.id, u.username)
    }
    return map
  }, [users])

  const getUsernameById = useCallback((userId: string | null) => {
    if (!userId) return 'System'
    return userMap.get(userId) ?? userId
  }, [userMap])

  const getActorLabel = useCallback((entry: AuditLogResponse['entries'][number]) => {
    const actorType = entry.actor_type ?? (entry.user_id ? 'user' : 'system')
    if (actorType === 'user') {
      return getUsernameById(entry.user_id)
    }
    if (actorType === 'device') return 'Device'
    if (actorType === 'anonymous') return 'Anonymous'
    return 'System'
  }, [getUsernameById])

  const total = data?.total ?? 0
  const entries = data?.entries ?? []
  const showingFrom = total > 0 ? offset + 1 : 0
  const showingTo = Math.min(offset + PAGE_SIZE, total)
  const catalogEntries = catalog?.entries ?? []
  const latestReview = reviews?.reviews?.[0]
  const canManageControls = user?.role === 'admin'

  const updateSettingsField = <K extends keyof AuditSettings>(key: K, value: AuditSettings[K]) => {
    setSettingsForm(prev => prev ? { ...prev, [key]: value } : prev)
  }

  const updateThresholdField = (key: keyof AuditSettings['thresholds'], value: number) => {
    setSettingsForm(prev => prev ? {
      ...prev,
      thresholds: {
        ...prev.thresholds,
        [key]: value,
      },
    } : prev)
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">Audit Logs</h2>
          <p className="text-sm text-text-muted mt-1">
            Health, export, review, detections, and immutable audit records.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
            className="inline-flex items-center gap-2 bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-3 py-2 transition-colors disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            {exportMutation.isPending ? 'Exporting…' : 'Export Audit Bundle'}
          </button>
        </div>
      </div>

      <div className="bg-surface border border-border rounded p-4">
        <div className="flex items-start gap-3">
          <div className="shrink-0 rounded-full bg-accent/10 p-2 text-accent">
            <Info className="w-4 h-4" />
          </div>
          <div className="space-y-3">
            <div>
              <div className="text-sm font-semibold text-text-primary">What this page tells you</div>
              <p className="text-xs text-text-muted mt-1">
                Use this page to answer four questions: is audit logging healthy, what happened, has someone reviewed it,
                and did any rule-based detections trigger.
              </p>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded border border-border bg-elevated/40 p-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-text-primary">Audit Health</div>
                <p className="text-xs text-text-muted mt-1">
                  This is the health of the audit pipeline itself. The failure counter tracks failed attempts to write
                  audit rows, not failed user logins or confirmed attacks.
                </p>
              </div>
              <div className="rounded border border-border bg-elevated/40 p-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-text-primary">Active Detections</div>
                <p className="text-xs text-text-muted mt-1">
                  These are simple threshold-based warnings such as repeated failed logins, failed registrations,
                  privileged-action bursts, or overdue reviews. They are prompts to investigate, not verdicts.
                </p>
              </div>
              <div className="rounded border border-border bg-elevated/40 p-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-text-primary">Review Workflow</div>
                <p className="text-xs text-text-muted mt-1">
                  This is manual review bookkeeping. You can save a filter, export a filtered set, record that you reviewed
                  it, and flag entries with notes for follow-up.
                </p>
              </div>
              <div className="rounded border border-border bg-elevated/40 p-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-text-primary">Audit Records</div>
                <p className="text-xs text-text-muted mt-1">
                  The table is a quick summary. Exporting the current view gives you the full JSON records with IDs,
                  details, resource metadata, correlation IDs, and the integrity hash chain.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="bg-surface border border-border rounded p-4">
          <div className="text-xs uppercase tracking-wider text-text-muted mb-1">Audit Health</div>
          <div className={`text-sm font-semibold ${health?.degraded ? 'text-status-error' : 'text-status-online'}`}>
            {health?.degraded ? 'Degraded' : 'Healthy'}
          </div>
          <div className="text-xs text-text-muted mt-2">Write failures: {health?.failure_count ?? 0}</div>
          <div className="text-xs text-text-muted mt-1">Last failure: {health?.last_failure_at ? formatDate(health.last_failure_at) : '—'}</div>
          <div className="text-xs text-text-muted mt-1">
            {health?.last_failure_reason ? `Reason: ${health.last_failure_reason}` : 'Counts are cumulative until reset.'}
          </div>
        </div>
        <div className="bg-surface border border-border rounded p-4">
          <div className="text-xs uppercase tracking-wider text-text-muted mb-1">Retention</div>
          <div className="text-sm font-semibold text-text-primary">{settings?.retention_days ?? 90} days</div>
          <div className="text-xs text-text-muted mt-2">Review cadence: every {settings?.review_reminder_days ?? 7} days</div>
          <div className="text-xs text-text-muted mt-1">Temp password TTL: {settings?.temporary_password_ttl_hours ?? 72} hours</div>
        </div>
        <div className="bg-surface border border-border rounded p-4">
          <div className="text-xs uppercase tracking-wider text-text-muted mb-1">Event Catalog</div>
          <div className="text-sm font-semibold text-text-primary">{catalogEntries.length} events</div>
          <div className="text-xs text-text-muted mt-2">Updated: {catalog?.last_updated_at ? formatDate(catalog.last_updated_at) : '—'}</div>
        </div>
        <div className="bg-surface border border-border rounded p-4">
          <div className="text-xs uppercase tracking-wider text-text-muted mb-1">Last Review</div>
          <div className="text-sm font-semibold text-text-primary">{latestReview ? latestReview.reviewer : 'None recorded'}</div>
          <div className="text-xs text-text-muted mt-2">{latestReview ? formatDate(latestReview.completed_at) : 'Create a review below'}</div>
        </div>
      </div>

      {detections?.detections && detections.detections.length > 0 && (
        <div className="bg-status-warning/10 border border-status-warning/20 rounded p-4">
          <div className="flex items-center gap-2 text-status-warning mb-3">
            <ShieldAlert className="w-4 h-4" />
            <span className="text-sm font-semibold">Active Detections</span>
          </div>
          <p className="text-xs text-text-muted mb-3">
            These notices are threshold-based prompts for review. They do not mean AeroDocs has confirmed malicious activity.
          </p>
          <div className="space-y-2">
            {detections.detections.map(detection => (
              <div key={detection.id} className="text-sm text-text-primary">
                <div className="font-medium">{detection.title}</div>
                <div className="text-text-muted text-xs mt-0.5">{detection.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="bg-surface border border-border rounded p-4 space-y-3">
          <div className="text-sm font-semibold text-text-primary">Compliance Controls</div>
          <p className="text-xs text-text-muted">
            These settings control retention, review reminders, password policy, and the thresholds used by active detections.
            Only admins can change them.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <label className="text-xs text-text-muted">
              <span>Retention Days</span>
              <input
                type="number"
                value={settingsForm?.retention_days ?? 90}
                onChange={e => updateSettingsField('retention_days', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
            <label className="text-xs text-text-muted">
              <span>Review Reminder Days</span>
              <input
                type="number"
                value={settingsForm?.review_reminder_days ?? 7}
                onChange={e => updateSettingsField('review_reminder_days', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
            <label className="text-xs text-text-muted">
              <span>Password History Count</span>
              <input
                type="number"
                value={settingsForm?.password_history_count ?? 5}
                onChange={e => updateSettingsField('password_history_count', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
            <label className="text-xs text-text-muted">
              <span>Temp Password TTL Hours</span>
              <input
                type="number"
                value={settingsForm?.temporary_password_ttl_hours ?? 72}
                onChange={e => updateSettingsField('temporary_password_ttl_hours', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
            <label className="text-xs text-text-muted">
              <span>Login Failures / Hour</span>
              <input
                type="number"
                value={settingsForm?.thresholds.login_failures_per_hour ?? 10}
                onChange={e => updateThresholdField('login_failures_per_hour', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
            <label className="text-xs text-text-muted">
              <span>Registration Failures / Hour</span>
              <input
                type="number"
                value={settingsForm?.thresholds.registration_failures_per_hour ?? 5}
                onChange={e => updateThresholdField('registration_failures_per_hour', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
            <label className="text-xs text-text-muted col-span-2">
              <span>Privileged Actions / Hour</span>
              <input
                type="number"
                value={settingsForm?.thresholds.privileged_actions_per_hour ?? 20}
                onChange={e => updateThresholdField('privileged_actions_per_hour', Number(e.target.value))}
                disabled={!canManageControls}
                className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60"
              />
            </label>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => settingsForm && settingsMutation.mutate(settingsForm)}
              disabled={!canManageControls || settingsMutation.isPending || !settingsForm}
              className="flex-1 bg-elevated hover:bg-base border border-border rounded px-3 py-2 text-sm text-text-primary transition-colors disabled:opacity-50"
            >
              {settingsMutation.isPending ? 'Saving…' : 'Save Controls'}
            </button>
            <button
              onClick={() => retentionMutation.mutate()}
              disabled={!canManageControls || retentionMutation.isPending}
              className="flex-1 bg-elevated hover:bg-base border border-border rounded px-3 py-2 text-sm text-text-primary transition-colors disabled:opacity-50"
            >
              {retentionMutation.isPending ? 'Running…' : 'Run Retention'}
            </button>
          </div>
          <div className="space-y-1 border-t border-border pt-3 text-xs text-text-muted">
            <div><span className="text-text-primary font-medium">Save Controls</span> stores the values above for future reminders, password policy checks, and detections.</div>
            <div><span className="text-text-primary font-medium">Run Retention</span> immediately deletes audit rows older than the retention window.</div>
          </div>
        </div>

        <div className="bg-surface border border-border rounded p-4 space-y-3">
          <div className="text-sm font-semibold text-text-primary">Review Workflow</div>
          <p className="text-xs text-text-muted">
            Recording a review does not approve, dismiss, or edit entries. It only stores who reviewed the current filtered
            set, when they reviewed it, and any notes they left.
          </p>
          <textarea
            value={reviewNotes}
            onChange={e => setReviewNotes(e.target.value)}
            placeholder="Review notes"
            className="w-full min-h-[100px] bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
          <button
            onClick={() => reviewMutation.mutate()}
            disabled={reviewMutation.isPending}
            className="w-full bg-elevated hover:bg-base border border-border rounded px-3 py-2 text-sm text-text-primary transition-colors disabled:opacity-50"
          >
            {reviewMutation.isPending ? 'Recording…' : 'Record Review Completion'}
          </button>
          <div className="space-y-2 border-t border-border pt-3">
            {(reviews?.reviews ?? []).map(review => (
              <div key={review.id} className="text-xs text-text-muted">
                <div className="text-text-primary">{review.reviewer}</div>
                <div>{formatDate(review.completed_at)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-surface border border-border rounded p-4 space-y-3">
          <div className="text-sm font-semibold text-text-primary">Saved Filters</div>
          <p className="text-xs text-text-muted">
            Save the current date, user, action, and outcome filters so common reviews can be reopened in one click.
          </p>
          <input
            type="text"
            value={savedFilterName}
            onChange={e => setSavedFilterName(e.target.value)}
            placeholder="Filter name"
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
          <button
            onClick={() => saveFilterMutation.mutate()}
            disabled={saveFilterMutation.isPending || !savedFilterName.trim()}
            className="w-full inline-flex items-center justify-center gap-2 bg-elevated hover:bg-base border border-border rounded px-3 py-2 text-sm text-text-primary transition-colors disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            Save Current Filters
          </button>
          <div className="space-y-2 border-t border-border pt-3">
            {(savedFilters?.filters ?? []).map(filter => (
              <div key={filter.id} className="flex items-center justify-between gap-2 text-xs">
                <button
                  onClick={() => {
                    const parsed = JSON.parse(filter.filters_json) as typeof filters
                    setFilters({
                      action: parsed.action ?? '',
                      userId: parsed.userId ?? '',
                      outcome: parsed.outcome ?? '',
                      from: parsed.from ?? '',
                      to: parsed.to ?? '',
                    })
                    setOffset(0)
                  }}
                  className="text-left text-text-primary hover:text-accent transition-colors"
                >
                  {filter.name}
                </button>
                <button
                  onClick={() => deleteFilterMutation.mutate(filter.id)}
                  className="text-text-muted hover:text-status-error transition-colors"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-surface border border-border rounded p-4 space-y-3">
          <div className="text-sm font-semibold text-text-primary">Event Catalog</div>
          <div className="space-y-2 max-h-64 overflow-auto pr-1">
            {catalogEntries.map(entry => (
              <div key={entry.action} className="text-xs border-b border-border last:border-b-0 pb-2">
                <div className="text-text-primary font-mono">{entry.action}</div>
                <div className="text-text-muted">{entry.label} · {entry.category}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="bg-surface border border-border rounded p-4 space-y-3">
          <div className="text-sm font-semibold text-text-primary">Export History</div>
          <p className="text-xs text-text-muted">
            This shows recent audit exports. Each export records who exported data, when they did it, and which filters were applied.
          </p>
          <div className="space-y-2">
            {(exportHistory?.entries ?? []).slice(0, 5).map(entry => (
              <div key={entry.id} className="text-xs text-text-muted border-b border-border last:border-b-0 pb-2">
                <div className="text-text-primary">{getActorLabel(entry)}</div>
                <div>{formatDate(entry.created_at)}</div>
                <div className="font-mono">{entry.detail ?? entry.action}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-surface border border-border rounded p-4 space-y-3">
          <div className="text-sm font-semibold text-text-primary">Flagged Events</div>
          <p className="text-xs text-text-muted">
            Flagging is a manual note for follow-up. It does not change the underlying audit record.
          </p>
          <div className="space-y-2">
            {(flags?.flags ?? []).map(flag => (
              <div key={flag.id} className="text-xs text-text-muted border-b border-border last:border-b-0 pb-2">
                <div className="text-text-primary">{flag.created_by}</div>
                <div>{formatDate(flag.created_at)}</div>
                <div>{flag.note}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Audit Log Records</h3>
        <p className="text-xs text-text-muted mb-3">
          The table shows the most useful summary fields for quick triage. When an entry includes extra context, it appears
          under the action. Export the current view if you need the full record payload.
        </p>

        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <input
            type="date"
            value={filters.from}
            onChange={e => updateFilter('from', e.target.value)}
            className="bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          />
          <input
            type="date"
            value={filters.to}
            onChange={e => updateFilter('to', e.target.value)}
            className="bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          />
          <select
            value={filters.userId}
            onChange={e => updateFilter('userId', e.target.value)}
            className="bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          >
            <option value="">All Users</option>
            {users.map(u => (
              <option key={u.id} value={u.id}>{u.username}</option>
            ))}
          </select>
          <select
            value={filters.action}
            onChange={e => updateFilter('action', e.target.value)}
            className="bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          >
            <option value="">All Actions</option>
            {catalogEntries.map(entry => (
              <option key={entry.action} value={entry.action}>{entry.action}</option>
            ))}
          </select>
          <select
            value={filters.outcome}
            onChange={e => updateFilter('outcome', e.target.value)}
            className="bg-elevated border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          >
            <option value="">All Outcomes</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
          </select>
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-accent hover:text-accent-hover text-sm transition-colors"
            >
              Clear Filters
            </button>
          )}
        </div>

        <div className="border border-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-surface border-b border-border">
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Timestamp</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Actor</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Action</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Outcome</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Target</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">IP Address</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Review</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-text-muted">Loading...</td></tr>
              )}
              {!isLoading && entries.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-text-muted">No audit log entries found.</td></tr>
              )}
              {!isLoading && entries.length > 0 && entries.map(entry => (
                <tr key={entry.id} className="border-b border-border last:border-b-0 hover:bg-surface/50">
                  <td className="px-4 py-2 text-text-secondary">{formatDate(entry.created_at)}</td>
                  <td className="px-4 py-2 text-text-primary">{getActorLabel(entry)}</td>
                  <td className="px-4 py-2">
                    <div className="space-y-1">
                      <span className="font-mono text-xs bg-elevated px-2 py-0.5 rounded text-text-secondary">{entry.action}</span>
                      {entry.detail && (
                        <div className="text-xs text-text-muted max-w-xs break-words">{entry.detail}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-text-muted capitalize">{entry.outcome ?? 'success'}</td>
                  <td className="px-4 py-2 text-text-muted font-mono text-xs">{entry.target ?? '—'}</td>
                  <td className="px-4 py-2 text-text-muted font-mono text-xs">{entry.ip_address ?? '—'}</td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => {
                        const note = globalThis.prompt?.('Flag note')
                        const trimmedNote = note?.trim()
                        if (trimmedNote) {
                          flagMutation.mutate({ entryId: entry.id, note: trimmedNote })
                        }
                      }}
                      className="text-xs text-accent hover:text-accent-hover transition-colors"
                    >
                      Flag
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {total > 0 && (
          <div className="flex items-center justify-between mt-3 text-sm text-text-muted">
            <span>Showing {showingFrom}-{showingTo} of {total}</span>
            <div className="flex gap-2">
              <button
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                disabled={offset === 0}
                className="px-3 py-1 border border-border rounded text-text-secondary hover:bg-surface disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => setOffset(offset + PAGE_SIZE)}
                disabled={offset + PAGE_SIZE >= total}
                className="px-3 py-1 border border-border rounded text-text-secondary hover:bg-surface disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
