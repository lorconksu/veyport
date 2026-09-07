import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cable, Save } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import type { LDAPConfig } from '@/types/api'

type LDAPForm = Omit<LDAPConfig, 'admin_groups' | 'auditor_groups' | 'viewer_groups' | 'terminal_groups'> & {
  admin_groups: string
  auditor_groups: string
  viewer_groups: string
  terminal_groups: string
}

const defaultLDAPConfig: LDAPConfig = {
  enabled: false,
  url: '',
  bind_dn: '',
  bind_password: '',
  bind_password_set: false,
  user_base_dn: '',
  group_base_dn: '',
  user_search_filter: '(uid={username})',
  group_search_filter: '(|(member={dn})(memberUid={username}))',
  username_attribute: 'uid',
  email_attribute: 'mail',
  external_id_attribute: 'entryUUID',
  group_name_attribute: 'cn',
  start_tls: false,
  tls_server_name: '',
  ca_cert_pem: '',
  allow_insecure_transport: false,
  admin_groups: ['veyport-admins'],
  auditor_groups: ['veyport-auditors'],
  viewer_groups: ['veyport-viewers'],
  terminal_groups: ['veyport-terminal-users'],
}

function joinGroups(groups: string[]) {
  return groups.join(', ')
}

function parseGroups(value: string) {
  const seen = new Set<string>()
  return value
    .split(/[,\n\r]+/)
    .map(group => group.trim())
    .filter(group => {
      if (!group || seen.has(group)) return false
      seen.add(group)
      return true
    })
}

function configToForm(config: LDAPConfig): LDAPForm {
  return {
    ...config,
    bind_password: '',
    admin_groups: joinGroups(config.admin_groups),
    auditor_groups: joinGroups(config.auditor_groups),
    viewer_groups: joinGroups(config.viewer_groups),
    terminal_groups: joinGroups(config.terminal_groups),
  }
}

function formToRequest(form: LDAPForm): LDAPConfig {
  return {
    ...form,
    admin_groups: parseGroups(form.admin_groups),
    auditor_groups: parseGroups(form.auditor_groups),
    viewer_groups: parseGroups(form.viewer_groups),
    terminal_groups: parseGroups(form.terminal_groups),
  }
}

export function DirectoryTab() {
  const { data, isLoading } = useQuery({
    queryKey: ['ldap-config'],
    queryFn: () => apiFetch<LDAPConfig>('/settings/ldap'),
  })

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">LDAP Directory</h3>
        <div className="bg-surface border border-border rounded p-4">
          {isLoading ? (
            <div className="text-text-muted text-sm py-4 text-center">Loading...</div>
          ) : (
            <DirectoryForm initialConfig={data ?? defaultLDAPConfig} />
          )}
        </div>
      </div>
    </div>
  )
}

function DirectoryForm({ initialConfig }: Readonly<{ initialConfig: LDAPConfig }>) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<LDAPForm>(() => configToForm(initialConfig))
  const [saveSuccess, setSaveSuccess] = useState('')
  const [testSuccess, setTestSuccess] = useState('')
  const [testError, setTestError] = useState('')

  const saveMutation = useMutation({
    mutationFn: (payload: LDAPConfig) =>
      apiFetch<{ status: string }>('/settings/ldap', {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ldap-config'] })
      setForm(prev => ({
        ...prev,
        bind_password: '',
        bind_password_set: prev.bind_password_set || prev.bind_password !== '',
      }))
      setSaveSuccess('LDAP configuration saved.')
      setTimeout(() => setSaveSuccess(''), 3000)
    },
  })

  const testMutation = useMutation({
    mutationFn: (payload: LDAPConfig) =>
      apiFetch<{ status: string }>('/settings/ldap/test', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      setTestSuccess('LDAP connection test passed.')
      setTestError('')
      setTimeout(() => setTestSuccess(''), 3000)
    },
    onError: (err: Error) => {
      setTestError(err.message || 'LDAP connection test failed.')
      setTestSuccess('')
    },
  })

  const handleChange = (field: keyof LDAPForm, value: string | boolean) => {
    setForm(prev => ({ ...prev, [field]: value }))
  }

  const handleSave = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSaveSuccess('')
    saveMutation.mutate(formToRequest(form))
  }

  const handleTest = () => {
    setTestSuccess('')
    setTestError('')
    testMutation.mutate(formToRequest(form))
  }

  return (
    <form onSubmit={handleSave} className="space-y-5">
      {saveMutation.isError && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
          {saveMutation.error instanceof Error ? saveMutation.error.message : 'Failed to save LDAP configuration'}
        </div>
      )}
      {saveSuccess && (
        <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
          {saveSuccess}
        </div>
      )}
      {testError && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
          {testError}
        </div>
      )}
      {testSuccess && (
        <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
          {testSuccess}
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <label className="flex items-center gap-2 cursor-pointer lg:col-span-2">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={e => handleChange('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-border accent-accent"
          />
          <span className="text-sm text-text-secondary">Enable LDAP</span>
        </label>

        <div className="lg:col-span-2">
          <label htmlFor="ldap-url" className="block text-xs text-text-muted mb-1">LDAP URL</label>
          <input
            id="ldap-url"
            type="text"
            placeholder="ldaps://freeipa.example.com:636"
            value={form.url}
            onChange={e => handleChange('url', e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
        </div>

        <div>
          <label htmlFor="ldap-bind-dn" className="block text-xs text-text-muted mb-1">Bind DN</label>
          <input
            id="ldap-bind-dn"
            type="text"
            placeholder="uid=veyport,cn=sysaccounts,cn=etc,dc=example,dc=com"
            value={form.bind_dn}
            onChange={e => handleChange('bind_dn', e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
        </div>

        <div>
          <label htmlFor="ldap-bind-password" className="block text-xs text-text-muted mb-1">Bind Password</label>
          <input
            id="ldap-bind-password"
            type="password"
            placeholder="New password"
            value={form.bind_password}
            onChange={e => handleChange('bind_password', e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
          {form.bind_password_set && form.bind_password === '' && (
            <div className="text-[10px] text-text-faint mt-1">Password is currently stored.</div>
          )}
        </div>

        <div>
          <label htmlFor="ldap-user-base-dn" className="block text-xs text-text-muted mb-1">User Base DN</label>
          <input
            id="ldap-user-base-dn"
            type="text"
            placeholder="cn=users,cn=accounts,dc=example,dc=com"
            value={form.user_base_dn}
            onChange={e => handleChange('user_base_dn', e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
        </div>

        <div>
          <label htmlFor="ldap-group-base-dn" className="block text-xs text-text-muted mb-1">Group Base DN</label>
          <input
            id="ldap-group-base-dn"
            type="text"
            placeholder="cn=groups,cn=accounts,dc=example,dc=com"
            value={form.group_base_dn}
            onChange={e => handleChange('group_base_dn', e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          />
        </div>
      </div>

      <div>
        <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">Role Mapping</h4>
        <div className="grid gap-3 lg:grid-cols-2">
          <TextInput id="ldap-admin-groups" label="Admin Groups" value={form.admin_groups} onChange={value => handleChange('admin_groups', value)} placeholder="freeipa-admins" />
          <TextInput id="ldap-auditor-groups" label="Auditor Groups" value={form.auditor_groups} onChange={value => handleChange('auditor_groups', value)} placeholder="freeipa-auditors" />
          <TextInput id="ldap-viewer-groups" label="Viewer Groups" value={form.viewer_groups} onChange={value => handleChange('viewer_groups', value)} placeholder="freeipa-viewers" />
          <TextInput id="ldap-terminal-groups" label="Terminal Groups" value={form.terminal_groups} onChange={value => handleChange('terminal_groups', value)} placeholder="bastion-users" />
        </div>
      </div>

      <div>
        <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">Search</h4>
        <div className="grid gap-3 lg:grid-cols-2">
          <TextInput id="ldap-user-filter" label="User Search Filter" value={form.user_search_filter} onChange={value => handleChange('user_search_filter', value)} placeholder="(uid={username})" />
          <TextInput id="ldap-group-filter" label="Group Search Filter" value={form.group_search_filter} onChange={value => handleChange('group_search_filter', value)} placeholder="(|(member={dn})(memberUid={username}))" />
          <TextInput id="ldap-username-attribute" label="Username Attribute" value={form.username_attribute} onChange={value => handleChange('username_attribute', value)} placeholder="uid" />
          <TextInput id="ldap-email-attribute" label="Email Attribute" value={form.email_attribute} onChange={value => handleChange('email_attribute', value)} placeholder="mail" />
          <TextInput id="ldap-external-id-attribute" label="External ID Attribute" value={form.external_id_attribute} onChange={value => handleChange('external_id_attribute', value)} placeholder="entryUUID" />
          <TextInput id="ldap-group-name-attribute" label="Group Name Attribute" value={form.group_name_attribute} onChange={value => handleChange('group_name_attribute', value)} placeholder="cn" />
        </div>
      </div>

      <div>
        <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">TLS</h4>
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="flex items-center gap-6 lg:col-span-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.start_tls}
                onChange={e => handleChange('start_tls', e.target.checked)}
                className="w-4 h-4 rounded border-border accent-accent"
              />
              <span className="text-sm text-text-secondary">StartTLS</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.allow_insecure_transport}
                onChange={e => handleChange('allow_insecure_transport', e.target.checked)}
                className="w-4 h-4 rounded border-border accent-accent"
              />
              <span className="text-sm text-text-secondary">Allow insecure transport</span>
            </label>
          </div>
          <TextInput id="ldap-tls-server-name" label="TLS Server Name" value={form.tls_server_name} onChange={value => handleChange('tls_server_name', value)} placeholder="freeipa.example.com" />
          <div className="lg:col-span-2">
            <label htmlFor="ldap-ca-cert" className="block text-xs text-text-muted mb-1">CA Certificate PEM</label>
            <textarea
              id="ldap-ca-cert"
              rows={5}
              value={form.ca_cert_pem}
              onChange={e => handleChange('ca_cert_pem', e.target.value)}
              className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent font-mono"
            />
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="submit"
          disabled={saveMutation.isPending}
          className="inline-flex items-center gap-2 bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-2 transition-colors disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {saveMutation.isPending ? 'Saving...' : 'Save LDAP Settings'}
        </button>
        <button
          type="button"
          onClick={handleTest}
          disabled={testMutation.isPending}
          className="inline-flex items-center gap-2 bg-elevated border border-border hover:border-accent text-text-secondary hover:text-text-primary text-sm rounded px-4 py-2 transition-colors disabled:opacity-50"
        >
          <Cable className="w-4 h-4" />
          {testMutation.isPending ? 'Testing...' : 'Test Connection'}
        </button>
      </div>
    </form>
  )
}

function TextInput({
  id,
  label,
  value,
  onChange,
  placeholder,
}: Readonly<{
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
}>) {
  return (
    <div>
      <label htmlFor={id} className="block text-xs text-text-muted mb-1">{label}</label>
      <input
        id={id}
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
      />
    </div>
  )
}
