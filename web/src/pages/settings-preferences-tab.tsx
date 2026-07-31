import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import type { NotificationPreference } from '@/types/api'

export function PreferencesTab() {
  const [localPrefs, setLocalPrefs] = useState<NotificationPreference[]>([])
  const [saveSuccess, setSaveSuccess] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['notification-prefs'],
    queryFn: () => apiFetch<{ preferences: NotificationPreference[] }>('/notifications/preferences'),
  })

  useEffect(() => {
    if (data?.preferences) {
      setLocalPrefs(data.preferences)
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: (preferences: Array<{ event_type: string; enabled: boolean }>) =>
      apiFetch<{ status: string }>('/notifications/preferences', {
        method: 'PUT',
        body: JSON.stringify({ preferences }),
      }),
    onSuccess: () => {
      setSaveSuccess('Preferences saved.')
      setTimeout(() => setSaveSuccess(''), 3000)
    },
  })

  const handleToggle = (event_type: string, enabled: boolean) => {
    setLocalPrefs(prev =>
      prev.map(p => p.event_type === event_type ? { ...p, enabled } : p),
    )
  }

  const handleSave = () => {
    setSaveSuccess('')
    saveMutation.mutate(
      localPrefs.map(p => ({ event_type: p.event_type, enabled: p.enabled })),
    )
  }

  // Group by category
  const grouped = localPrefs.reduce<Record<string, NotificationPreference[]>>((acc, pref) => {
    const cat = pref.category || 'Other'
    if (!acc[cat]) acc[cat] = []
    acc[cat].push(pref)
    return acc
  }, {})

  const categories = Object.keys(grouped).sort((a, b) => a.localeCompare(b))

  return (
    <div className="max-w-lg space-y-6">
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-1">Email Notification Preferences</h3>
        <p className="text-xs text-text-muted">Choose which events you want to receive email notifications for.</p>
      </div>

      {isLoading && (
        <div className="text-text-muted text-sm py-4 text-center">Loading...</div>
      )}

      {!isLoading && categories.length === 0 && (
        <div className="text-text-muted text-sm">No notification preferences available.</div>
      )}

      {!isLoading && categories.map(category => (
        <div key={category}>
          <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">{category}</h4>
          <div className="bg-surface border border-border rounded divide-y divide-border">
            {grouped[category].map(pref => (
              <label
                key={pref.event_type}
                className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-elevated/50 transition-colors"
              >
                <div>
                  <div className="text-sm text-text-primary">{pref.label}</div>
                  <div className="text-xs text-text-muted font-mono">{pref.event_type}</div>
                </div>
                <input
                  type="checkbox"
                  aria-label={pref.label}
                  checked={pref.enabled}
                  onChange={e => handleToggle(pref.event_type, e.target.checked)}
                  className="w-4 h-4 rounded border-border accent-accent"
                />
              </label>
            ))}
          </div>
        </div>
      ))}

      {!isLoading && (
        <div>
          {saveMutation.isError && (
            <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
              {saveMutation.error instanceof Error ? saveMutation.error.message : 'Failed to save preferences'}
            </div>
          )}
          {saveSuccess && (
            <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2 mb-3">
              {saveSuccess}
            </div>
          )}
          <button
            type="button"
            onClick={handleSave}
            disabled={saveMutation.isPending}
            className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-2 transition-colors disabled:opacity-50"
          >
            {saveMutation.isPending ? 'Saving...' : 'Save Preferences'}
          </button>
        </div>
      )}
    </div>
  )
}
