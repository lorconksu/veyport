import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import type { HubConfig } from '@/types/api'

type PolicyField = 'lockout_threshold' | 'lockout_window_minutes' | 'lockout_duration_minutes' | 'dormant_days'

const FIELDS: { key: PolicyField; label: string; helper: string; id: string }[] = [
  { key: 'lockout_threshold', label: 'Lockout threshold (failures)', helper: '0 disables locking', id: 'policy-lockout-threshold' },
  { key: 'lockout_window_minutes', label: 'Lockout window (minutes)', helper: '', id: 'policy-lockout-window-minutes' },
  { key: 'lockout_duration_minutes', label: 'Lock duration (minutes)', helper: '0 = no auto-unlock', id: 'policy-lockout-duration-minutes' },
  { key: 'dormant_days', label: 'Dormant after (days)', helper: '0 disables dormancy', id: 'policy-dormant-days' },
]

const NON_NEGATIVE_INTEGER = /^\d+$/

/**
 * "Account policy" card (Settings → Users, admin): the four lockout/dormancy
 * fields from HubConfig, editable together. Mirrors HubConfigSection's
 * loading/error/success visual language (settings-notifications-tab.tsx).
 */
export function AccountPolicyCard() {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<Record<PolicyField, string>>({
    lockout_threshold: '',
    lockout_window_minutes: '',
    lockout_duration_minutes: '',
    dormant_days: '',
  })
  const [formLoaded, setFormLoaded] = useState(false)
  const [errors, setErrors] = useState<Partial<Record<PolicyField, string>>>({})
  const [success, setSuccess] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['hub-config'],
    queryFn: () => apiFetch<HubConfig>('/settings/hub'),
  })

  useEffect(() => {
    if (data && !formLoaded) {
      setForm({
        lockout_threshold: String(data.lockout_threshold ?? 0),
        lockout_window_minutes: String(data.lockout_window_minutes ?? 0),
        lockout_duration_minutes: String(data.lockout_duration_minutes ?? 0),
        dormant_days: String(data.dormant_days ?? 0),
      })
      setFormLoaded(true)
    }
  }, [data, formLoaded])

  const saveMutation = useMutation({
    mutationFn: (body: Record<PolicyField, number>) =>
      apiFetch('/settings/hub', {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hub-config'] })
      setSuccess('Account policy saved.')
      setTimeout(() => setSuccess(''), 3000)
    },
  })

  const handleChange = (field: PolicyField, value: string) => {
    setForm(prev => ({ ...prev, [field]: value }))
  }

  const handleSave = () => {
    setSuccess('')
    saveMutation.reset()

    const nextErrors: Partial<Record<PolicyField, string>> = {}
    const parsed: Partial<Record<PolicyField, number>> = {}

    for (const { key } of FIELDS) {
      const raw = form[key].trim()
      if (!NON_NEGATIVE_INTEGER.test(raw)) {
        nextErrors[key] = 'Must be a non-negative integer'
      } else {
        parsed[key] = Number.parseInt(raw, 10)
      }
    }

    setErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) return

    saveMutation.mutate(parsed as Record<PolicyField, number>)
  }

  return (
    <div className="mb-6">
      <h3 className="text-sm font-semibold text-text-primary mb-3">Account policy</h3>
      <div className="bg-surface border border-border rounded p-4">
        {isLoading ? (
          <div className="text-text-muted text-sm py-4 text-center">Loading...</div>
        ) : (
          <div className="space-y-3 max-w-lg">
            {saveMutation.isError && (
              <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
                {saveMutation.error instanceof Error ? saveMutation.error.message : 'Failed to save account policy'}
              </div>
            )}
            {success && (
              <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
                {success}
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              {FIELDS.map(({ key, label, helper, id }) => (
                <div key={key}>
                  <label htmlFor={id} className="block text-xs text-text-muted mb-1">{label}</label>
                  <input
                    id={id}
                    type="number"
                    value={form[key]}
                    onChange={e => handleChange(key, e.target.value)}
                    className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                  />
                  {helper && !errors[key] && (
                    <p className="text-[10px] text-text-faint mt-1">{helper}</p>
                  )}
                  {errors[key] && (
                    <p className="text-[10px] text-status-error mt-1">{errors[key]}</p>
                  )}
                </div>
              ))}
            </div>

            <button
              type="button"
              onClick={handleSave}
              disabled={saveMutation.isPending}
              className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-2 transition-colors disabled:opacity-50"
            >
              {saveMutation.isPending ? 'Saving...' : 'Save'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
