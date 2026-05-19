import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import type { SMTPConfig, NotificationLogEntry } from '@/types/api'

export function NotificationsTab() {
  const queryClient = useQueryClient()

  // SMTP form state
  const [form, setForm] = useState<SMTPConfig>({
    host: '',
    port: 587,
    username: '',
    password: '',
    from: '',
    tls: true,
    enabled: false,
  })
  const [formLoaded, setFormLoaded] = useState(false)
  const [smtpSuccess, setSmtpSuccess] = useState('')

  // Test email state
  const [testRecipient, setTestRecipient] = useState('')
  const [testSuccess, setTestSuccess] = useState('')
  const [testError, setTestError] = useState('')

  const { data: smtpData, isLoading: smtpLoading } = useQuery({
    queryKey: ['smtp-config'],
    queryFn: () => apiFetch<SMTPConfig>('/settings/smtp'),
  })

  useEffect(() => {
    if (smtpData && !formLoaded) {
      setForm(smtpData)
      setFormLoaded(true)
    }
  }, [smtpData, formLoaded])

  const saveMutation = useMutation({
    mutationFn: (data: SMTPConfig) =>
      apiFetch<SMTPConfig>('/settings/smtp', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['smtp-config'] })
      setSmtpSuccess('SMTP configuration saved.')
      setTimeout(() => setSmtpSuccess(''), 3000)
    },
  })

  const testMutation = useMutation({
    mutationFn: (recipient: string) =>
      apiFetch<{ status: string }>('/settings/smtp/test', {
        method: 'POST',
        body: JSON.stringify({ recipient }),
      }),
    onSuccess: () => {
      setTestSuccess('Test email sent successfully.')
      setTestError('')
      setTimeout(() => setTestSuccess(''), 3000)
    },
    onError: (err: Error) => {
      setTestError(err.message || 'Failed to send test email.')
      setTestSuccess('')
    },
  })

  const { data: logData, isLoading: logLoading } = useQuery({
    queryKey: ['notification-log'],
    queryFn: () => apiFetch<{ entries: NotificationLogEntry[]; total: number }>('/notifications/log'),
  })

  const handleFormChange = (field: keyof SMTPConfig, value: string | number | boolean) => {
    setForm(prev => ({ ...prev, [field]: value }))
  }

  const handleSave = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSmtpSuccess('')
    saveMutation.mutate(form)
  }

  const handleTest = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!testRecipient) return
    setTestSuccess('')
    setTestError('')
    testMutation.mutate(testRecipient)
  }

  const formatDate = (iso: string) => {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const entries = logData?.entries ?? []

  return (
    <div className="space-y-8">
      {/* Section 1: SMTP Configuration */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">SMTP Configuration</h3>
        <div className="bg-surface border border-border rounded p-4">
          {smtpLoading && (
            <div className="text-text-muted text-sm py-4 text-center">Loading...</div>
          )}
          {!smtpLoading && (
            <form onSubmit={handleSave} className="space-y-3 max-w-lg">
              {saveMutation.isError && (
                <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
                  {saveMutation.error instanceof Error ? saveMutation.error.message : 'Failed to save SMTP configuration'}
                </div>
              )}
              {smtpSuccess && (
                <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
                  {smtpSuccess}
                </div>
              )}

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label htmlFor="smtp-host" className="block text-xs text-text-muted mb-1">Host</label>
                  <input
                    id="smtp-host"
                    type="text"
                    placeholder="smtp.example.com"
                    value={form.host}
                    onChange={e => handleFormChange('host', e.target.value)}
                    className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                  />
                </div>
                <div>
                  <label htmlFor="smtp-port" className="block text-xs text-text-muted mb-1">Port</label>
                  <input
                    id="smtp-port"
                    type="number"
                    placeholder="587"
                    value={form.port}
                    onChange={e => handleFormChange('port', Number.parseInt(e.target.value, 10) || 0)}
                    className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                  />
                </div>
              </div>

              <div>
                <label htmlFor="smtp-username" className="block text-xs text-text-muted mb-1">Username</label>
                <input
                  id="smtp-username"
                  type="text"
                  placeholder="user@example.com"
                  value={form.username}
                  onChange={e => handleFormChange('username', e.target.value)}
                  className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                />
              </div>

              <div>
                <label htmlFor="smtp-password" className="block text-xs text-text-muted mb-1">Password</label>
                <input
                  id="smtp-password"
                  type="password"
                  placeholder="••••••••"
                  value={form.password}
                  onChange={e => handleFormChange('password', e.target.value)}
                  className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                />
              </div>

              <div>
                <label htmlFor="smtp-from" className="block text-xs text-text-muted mb-1">From Address</label>
                <input
                  id="smtp-from"
                  type="text"
                  placeholder="Veyport <noreply@example.com>"
                  value={form.from}
                  onChange={e => handleFormChange('from', e.target.value)}
                  className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                />
              </div>

              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.tls}
                    onChange={e => handleFormChange('tls', e.target.checked)}
                    className="w-4 h-4 rounded border-border accent-accent"
                  />
                  <span className="text-sm text-text-secondary">Use TLS</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={e => handleFormChange('enabled', e.target.checked)}
                    className="w-4 h-4 rounded border-border accent-accent"
                  />
                  <span className="text-sm text-text-secondary">Enable SMTP</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={saveMutation.isPending}
                className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-2 transition-colors disabled:opacity-50"
              >
                {saveMutation.isPending ? 'Saving...' : 'Save SMTP Settings'}
              </button>
            </form>
          )}

          {/* Test email */}
          {!smtpLoading && (
            <div className="mt-5 pt-5 border-t border-border max-w-lg">
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">Send Test Email</h4>
              {testSuccess && (
                <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2 mb-3">
                  {testSuccess}
                </div>
              )}
              {testError && (
                <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
                  {testError}
                </div>
              )}
              <form onSubmit={handleTest} className="flex gap-2">
                <input
                  type="email"
                  placeholder="recipient@example.com"
                  value={testRecipient}
                  onChange={e => setTestRecipient(e.target.value)}
                  className="flex-1 bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                  required
                />
                <button
                  type="submit"
                  disabled={testMutation.isPending || !testRecipient}
                  className="bg-elevated border border-border hover:border-accent text-text-secondary hover:text-text-primary text-sm rounded px-4 py-2 transition-colors disabled:opacity-50"
                >
                  {testMutation.isPending ? 'Sending...' : 'Send Test'}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>

      {/* Section 2: Hub Configuration */}
      <HubConfigSection />

      {/* Section 3: Notification Log */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Notification Log</h3>
        <div className="border border-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-surface border-b border-border">
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Date</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Recipient</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Event</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Subject</th>
                <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody>
              {logLoading && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-text-muted">Loading...</td>
                </tr>
              )}
              {!logLoading && entries.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-text-muted">No notifications sent yet</td>
                </tr>
              )}
              {!logLoading && entries.map(entry => (
                <tr key={entry.id} className="border-b border-border last:border-b-0 hover:bg-surface/50">
                  <td className="px-4 py-2 text-text-muted text-xs whitespace-nowrap">{formatDate(entry.created_at)}</td>
                  <td className="px-4 py-2 text-text-secondary">{entry.username}</td>
                  <td className="px-4 py-2 text-text-secondary font-mono text-xs">{entry.event_type}</td>
                  <td className="px-4 py-2 text-text-primary">{entry.subject}</td>
                  <td className="px-4 py-2">
                    {entry.status === 'sent' ? (
                      <span className="text-xs text-status-online">Sent</span>
                    ) : (
                      <span className="text-xs text-status-error">Failed</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function HubConfigSection() {
  const queryClient = useQueryClient()
  const [grpcAddr, setGrpcAddr] = useState('')
  const [success, setSuccess] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['hub-config'],
    queryFn: () => apiFetch<{ grpc_external_addr: string }>('/settings/hub'),
  })

  useEffect(() => {
    if (data) setGrpcAddr(data.grpc_external_addr)
  }, [data])

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/settings/hub', {
        method: 'PUT',
        body: JSON.stringify({ grpc_external_addr: grpcAddr }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hub-config'] })
      setSuccess('Hub configuration saved.')
      setTimeout(() => setSuccess(''), 3000)
    },
  })

  return (
    <div>
      <h3 className="text-sm font-semibold text-text-primary mb-3">Hub Configuration</h3>
      <div className="bg-surface border border-border rounded p-4">
        {isLoading ? (
          <div className="text-text-muted text-sm py-4 text-center">Loading...</div>
        ) : (
          <div className="space-y-3 max-w-lg">
            {success && (
              <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
                {success}
              </div>
            )}
            <div>
              <label htmlFor="grpc-external-addr" className="block text-xs text-text-muted mb-1">
                gRPC External Address
              </label>
              <input
                id="grpc-external-addr"
                type="text"
                placeholder="hub.example.com:9443"
                value={grpcAddr}
                onChange={e => setGrpcAddr(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
              />
              <p className="text-[10px] text-text-faint mt-1">
                The address agents use for gRPC connections. Used in the install command when adding new servers.
                Leave empty to use the default (hostname:9443).
              </p>
            </div>
            <button
              type="button"
              onClick={() => saveMutation.mutate()}
              className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-2 transition-colors"
            >
              Save
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
