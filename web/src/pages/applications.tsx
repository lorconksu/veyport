import { useState } from 'react'
import { ExternalLink, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiFetch } from '@/lib/api'
import { hasCapability } from '@/lib/auth'
import { useAuth } from '@/hooks/use-auth'
import {
  useAdminApplications,
  useApplicationGroup,
  useApplicationDirectoryGroups,
  useApplicationGroups,
  useApplicationGrants,
  useApplicationMutations,
  useApplicationSessions,
  useApplicationSettings,
  useApplicationUserSubjects,
  useAuthorizedApplications,
} from '@/hooks/use-application-access'
import type {
  ApplicationConfig,
  ApplicationConfigInput,
  ApplicationGrantKind,
  ApplicationGroup,
  ApplicationSettings,
} from '@/types/application-access'

type Panel = 'available' | 'applications' | 'groups' | 'policy'
const PAGE_SIZE = 50
const inputClass = 'w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent'
const labelClass = 'block text-xs text-text-muted mb-1'

function ErrorBox({ message }: Readonly<{ message: string }>) {
  return <div role="alert" className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">{message}</div>
}

function Pagination({ offset, total, onChange }: Readonly<{ offset: number; total: number; onChange: (offset: number) => void }>) {
  if (total <= PAGE_SIZE) return null
  return <div className="flex items-center justify-between text-xs text-text-muted pt-3">
    <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
    <div className="flex gap-2">
      <button type="button" className="rounded border border-border px-3 py-1 disabled:opacity-40" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
      <button type="button" className="rounded border border-border px-3 py-1 disabled:opacity-40" disabled={offset + PAGE_SIZE >= total} onClick={() => onChange(offset + PAGE_SIZE)}>Next</button>
    </div>
  </div>
}

function ApplicationSessions() {
  const [offset, setOffset] = useState(0)
  const { data, isLoading, isError, error, refetch } = useApplicationSessions(offset)
  const { revokeSession } = useApplicationMutations()
  const sessions = data?.sessions ?? []
  return <section className="mt-8">
    <div className="flex items-center justify-between mb-3">
      <div><h2 className="text-sm font-semibold text-text-primary">Your application sessions</h2><p className="text-xs text-text-muted mt-1">These sessions use their own idle and maximum lifetime.</p></div>
      <button type="button" onClick={() => void refetch()} className="text-text-muted hover:text-text-primary" aria-label="Refresh application sessions"><RefreshCw className="w-4 h-4" /></button>
    </div>
    <div className="bg-surface border border-border rounded overflow-hidden">
      {isLoading && <p className="p-4 text-sm text-text-muted">Loading sessions…</p>}
      {isError && <div className="p-4"><ErrorBox message={error instanceof Error ? error.message : 'Could not load application sessions.'} /></div>}
      {!isLoading && !isError && sessions.length === 0 && <p className="p-4 text-sm text-text-muted">You have no active application sessions.</p>}
      {sessions.length > 0 && <div className="divide-y divide-border">
        {sessions.map(session => {
          const ended = !!session.ended_at || !!session.end_reason
          const appName = session.application_name || `Application ${session.application_id}`
          return <div key={session.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
            <div className="min-w-48 flex-1"><div className="text-sm text-text-primary">{appName}</div><div className="text-xs text-text-muted">Last used {new Date(session.last_seen_at).toLocaleString()}</div>{session.end_reason && <div className="text-xs text-text-faint mt-1">Ended: {session.end_reason.replaceAll('_', ' ')}</div>}</div>
            <div className="text-xs text-text-muted">{session.idle_deadline_at && <div>Idle end {new Date(session.idle_deadline_at).toLocaleString()}</div>}<div>Maximum {new Date(session.expires_at).toLocaleString()}</div></div>
            {!ended && <button type="button" disabled={revokeSession.isPending} onClick={() => {
              if (window.confirm(`End your ${appName} session?`)) revokeSession.mutate(session.id)
            }} className="text-xs text-status-error hover:underline disabled:opacity-50">End session</button>}
          </div>
        })}
      </div>}
      {revokeSession.isError && <div className="p-3"><ErrorBox message={revokeSession.error instanceof Error ? revokeSession.error.message : 'Could not end application session.'} /></div>}
    </div>
    {!isLoading && !isError && <Pagination offset={offset} total={data?.total ?? 0} onChange={setOffset} />}
  </section>
}

function AvailableApplications() {
  const [offset, setOffset] = useState(0)
  const { data, isLoading, isError, error, refetch } = useAuthorizedApplications(offset)
  const apps = data?.applications ?? []
  return <>
    <div className="flex items-end justify-between gap-4 mb-5">
      <div><h1 className="text-xl font-semibold text-text-primary">Applications</h1><p className="mt-1 text-sm text-text-muted">Open the tools available to your account.</p></div>
      <button type="button" onClick={() => void refetch()} className="text-xs text-text-muted hover:text-text-primary flex items-center gap-2"><RefreshCw className="w-4 h-4" />Refresh</button>
    </div>
    {isLoading && <div className="text-sm text-text-muted py-8 text-center">Loading applications…</div>}
    {isError && <ErrorBox message={error instanceof Error ? error.message : 'Could not load applications.'} />}
    {!isLoading && !isError && apps.length === 0 && <div className="bg-surface border border-border rounded p-8 text-center text-sm text-text-muted">No applications are available for your account yet.</div>}
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {apps.map(app => <article key={app.id} className="bg-surface border border-border rounded p-4 flex flex-col min-h-36">
        <div className="font-semibold text-text-primary">{app.name}</div>
        <p className="text-sm text-text-muted mt-2 flex-1">{app.description || 'Open this application using your Veyport account.'}</p>
        {!app.available && <p className="text-xs text-status-warning mt-3">Temporarily unavailable{app.availability_reason ? `: ${app.availability_reason}` : ''}</p>}
        <div className="mt-4 flex justify-end">
          <Link aria-disabled={!app.available} onClick={e => { if (!app.available) e.preventDefault() }} to={`/applications/${encodeURIComponent(app.id)}/launch`} target="_blank" rel="noopener noreferrer" className={`inline-flex items-center gap-2 text-sm font-medium ${app.available ? 'text-accent hover:underline' : 'text-text-faint pointer-events-none'}`}>
            Open application <ExternalLink className="w-4 h-4" />
          </Link>
        </div>
      </article>)}
    </div>
    {!isLoading && !isError && <Pagination offset={offset} total={data?.total ?? 0} onChange={setOffset} />}
    <ApplicationSessions />
  </>
}

const blankConfig: ApplicationConfigInput = { name: '', slug: '', description: '', route: 'hub', backend_url: '', allowed_cidrs: [], ca_pem: '', enabled: true }

function configInput(app?: ApplicationConfig): ApplicationConfigInput {
  return app ? {
    name: app.name, slug: app.slug, description: app.description, route: app.route,
    node_id: app.node_id ?? '', backend_url: app.backend_url,
    allowed_cidrs: app.allowed_cidrs ?? [], ca_pem: app.ca_pem ?? '', enabled: app.enabled,
  } : { ...blankConfig }
}

function ApplicationEditor({ app, onClose }: Readonly<{ app?: ApplicationConfig; onClose: () => void }>) {
  const [form, setForm] = useState<ApplicationConfigInput>(() => configInput(app))
  const [cidrText, setCidrText] = useState((app?.allowed_cidrs ?? []).join('\n'))
  const { create, update } = useApplicationMutations()
  const [nodeOffset, setNodeOffset] = useState(0)
  const nodes = useQuery({
    queryKey: ['servers', 'application-select', nodeOffset],
    enabled: form.route === 'node',
    queryFn: () => apiFetch<{ servers: Array<{ id: string; name: string; status: string }>; total: number }>(`/servers?limit=50&offset=${nodeOffset}`),
  })
  const mutation = app ? update : create
  const set = <K extends keyof ApplicationConfigInput>(key: K, value: ApplicationConfigInput[K]) => setForm(prev => ({ ...prev, [key]: value }))
  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    const value = { ...form, allowed_cidrs: cidrText.split(/[\n,]+/).map(s => s.trim()).filter(Boolean) }
    if (app) update.mutate({ id: app.id, value, expectedVersion: app.config_version }, { onSuccess: onClose })
    else create.mutate(value, { onSuccess: onClose })
  }
  return <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center overflow-y-auto p-4" role="presentation">
    <form onSubmit={submit} className="bg-surface border border-border rounded w-full max-w-2xl p-5 space-y-4 my-6" aria-label={app ? 'Edit application' : 'Add application'}>
      <div className="flex items-start justify-between"><div><h2 className="text-lg font-semibold">{app ? 'Edit application' : 'Add application'}</h2><p className="text-xs text-text-muted mt-1">Configure the private service Veyport will connect to.</p></div><button type="button" onClick={onClose} className="text-sm text-text-muted">Close</button></div>
      {mutation.isError && <ErrorBox message={mutation.error instanceof Error ? mutation.error.message : 'Could not save application.'} />}
      <div className="grid sm:grid-cols-2 gap-3">
        <div><label className={labelClass} htmlFor="app-name">Name</label><input id="app-name" className={inputClass} required maxLength={120} value={form.name} onChange={e => set('name', e.target.value)} /></div>
        <div><label className={labelClass} htmlFor="app-slug">Short name</label><input id="app-slug" className={inputClass} required maxLength={63} pattern="[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" value={form.slug} onChange={e => set('slug', e.target.value)} /><p className="text-[11px] text-text-faint mt-1">Used for the application’s Veyport address.</p></div>
        <div className="sm:col-span-2"><label className={labelClass} htmlFor="app-description">Description</label><input id="app-description" className={inputClass} maxLength={500} value={form.description} onChange={e => set('description', e.target.value)} /></div>
        <div><label className={labelClass} htmlFor="app-route">Connect through</label><select id="app-route" className={inputClass} value={form.route} onChange={e => set('route', e.target.value as 'hub' | 'node')}><option value="hub">Veyport hub</option><option value="node">A connected node</option></select></div>
        {form.route === 'node' && <div><label className={labelClass} htmlFor="app-node">Connected node</label><select id="app-node" className={inputClass} required value={form.node_id ?? ''} onChange={e => set('node_id', e.target.value)}><option value="">Choose a node…</option>{form.node_id && !(nodes.data?.servers ?? []).some(node => node.id === form.node_id) && <option value={form.node_id}>Current node · {form.node_id}</option>}{(nodes.data?.servers ?? []).map(node => <option key={node.id} value={node.id}>{node.name} · {node.status}</option>)}</select>{nodes.isError && <p className="text-xs text-status-error mt-1">Could not load nodes. Refresh and try again.</p>}<Pagination offset={nodeOffset} total={nodes.data?.total ?? 0} onChange={setNodeOffset} /></div>}
        <div className="sm:col-span-2"><label className={labelClass} htmlFor="app-backend">Application address</label><input id="app-backend" type="url" className={inputClass} required placeholder="https://service.internal:8443/base" value={form.backend_url} onChange={e => set('backend_url', e.target.value)} /><p className="text-[11px] text-text-faint mt-1">Use an http or https address with no username, password, query, or fragment. Veyport connects from the selected route.</p></div>
        <div className="sm:col-span-2"><label className={labelClass} htmlFor="app-cidrs">Allowed network ranges</label><textarea id="app-cidrs" rows={3} required className={inputClass} placeholder={'10.20.0.0/16\nfd00:20::/64'} value={cidrText} onChange={e => setCidrText(e.target.value)} /><p className="text-[11px] text-text-faint mt-1">Enter the IP ranges the application may resolve to, one per line. The server checks each address before connecting.</p></div>
        <div className="sm:col-span-2"><label className={labelClass} htmlFor="app-ca">Private certificate authority (optional)</label><textarea id="app-ca" rows={3} className={inputClass} placeholder={app ? 'Paste a certificate, or leave blank to remove private CA trust.' : '-----BEGIN CERTIFICATE-----'} value={form.ca_pem ?? ''} onChange={e => set('ca_pem', e.target.value)} /><p className="text-[11px] text-text-faint mt-1">Only the certificate is stored. Private keys are not accepted.</p></div>
        <label className="sm:col-span-2 flex items-center gap-2 text-sm text-text-secondary"><input type="checkbox" checked={form.enabled} onChange={e => set('enabled', e.target.checked)} />Application is enabled</label>
      </div>
      <div className="flex justify-end gap-2"><button type="button" onClick={onClose} className="border border-border rounded px-3 py-2 text-sm">Cancel</button><button type="submit" disabled={mutation.isPending} className="bg-accent text-white rounded px-4 py-2 text-sm disabled:opacity-50">{mutation.isPending ? 'Saving…' : app ? 'Save changes' : 'Create application'}</button></div>
    </form>
  </div>
}

const grantLabels: Record<ApplicationGrantKind, string> = { user: 'Person', role: 'Role', local_group: 'Application group', directory_group: 'Directory group' }

function GrantEditor({ app, onClose }: Readonly<{ app: ApplicationConfig; onClose: () => void }>) {
  const { data, isLoading, isError, error } = useApplicationGrants(app.id)
  const [groupOffset, setGroupOffset] = useState(0)
  const [userOffset, setUserOffset] = useState(0)
  const [userSearch, setUserSearch] = useState('')
  const [directorySearch, setDirectorySearch] = useState('')
  const [kind, setKind] = useState<ApplicationGrantKind>('user')
  const [subject, setSubject] = useState('')
  const groupsQuery = useApplicationGroups(groupOffset, kind === 'local_group')
  const usersQuery = useApplicationUserSubjects(userOffset, userSearch, kind === 'user')
  const directoryQuery = useApplicationDirectoryGroups(directorySearch, kind === 'directory_group')
  const { grants: saveGrants } = useApplicationMutations()
  const current = data?.grants ?? []
  const choices = kind === 'role'
    ? ['admin', 'auditor', 'viewer', 'security-officer', 'security-approver', 'original-reader']
    : kind === 'local_group' ? groupsQuery.data?.groups?.map(group => group.id) ?? []
      : kind === 'user' ? usersQuery.data?.users?.map(user => user.id) ?? [] : []
  const userNames = new Map((usersQuery.data?.users ?? []).map(user => [user.id, `${user.username} (${user.id})`]))
  const groupNames = new Map((groupsQuery.data?.groups ?? []).map(group => [group.id, `${group.name} (${group.id})`]))
  const directoryNames = new Map((directoryQuery.data?.groups ?? []).map(group => [group.subject_id, `${group.name} (${group.subject_id})`]))
  const addGrant = () => {
    const value = subject.trim()
    if (!value || current.some(grant => grant.kind === kind && grant.subject_id === value)) return
    saveGrants.mutate({ id: app.id, grants: [...current, { kind, subject_id: value }], expectedVersion: data?.config_version ?? app.config_version }, { onSuccess: () => setSubject('') })
  }
  const removeGrant = (entry: { kind: ApplicationGrantKind; subject_id: string }) => {
    if (!window.confirm(`Remove this ${grantLabels[entry.kind].toLowerCase()} grant? Anyone relying on it may lose access and have active application sessions ended.`)) return
    saveGrants.mutate({ id: app.id, grants: current.filter(g => g.kind !== entry.kind || g.subject_id !== entry.subject_id), expectedVersion: data?.config_version ?? app.config_version })
  }
  return <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center overflow-y-auto p-4"><div className="bg-surface border border-border rounded w-full max-w-2xl p-5 my-6" role="dialog" aria-modal="true" aria-label={`Access for ${app.name}`}>
    <div className="flex justify-between"><div><h2 className="text-lg font-semibold">Who can open {app.name}?</h2><p className="text-xs text-text-muted mt-1">A person can receive access through any listed person, role, or group grant.</p></div><button type="button" onClick={onClose} className="text-sm text-text-muted">Close</button></div>
    {isLoading && <p className="text-sm text-text-muted py-5">Loading access rules…</p>}
    {isError && <div className="mt-4"><ErrorBox message={error instanceof Error ? error.message : 'Could not load access rules.'} /></div>}
    {!isLoading && !isError && <>
      <div className="mt-4 flex flex-wrap gap-2">
        <select aria-label="Grant type" className={`${inputClass} max-w-48`} value={kind} onChange={e => { setKind(e.target.value as ApplicationGrantKind); setSubject('') }}>{Object.entries(grantLabels).map(([value, title]) => <option key={value} value={value}>{title}</option>)}</select>
        {kind === 'directory_group' ? <><input className={`${inputClass} flex-1 min-w-48`} aria-label="Search directory groups" placeholder="Search directory groups" value={directorySearch} onChange={e => { setDirectorySearch(e.target.value); setSubject('') }} /><select className={`${inputClass} flex-1 min-w-48`} aria-label="Directory group" value={subject} onChange={e => setSubject(e.target.value)}><option value="">Choose a directory group…</option>{(directoryQuery.data?.groups ?? []).map(group => <option key={group.subject_id} value={group.subject_id}>{group.name}</option>)}</select></> : <>
          {kind === 'user' && <input className={`${inputClass} flex-1 min-w-48`} aria-label="Search people for grant" placeholder="Search people" value={userSearch} onChange={e => { setUserSearch(e.target.value); setUserOffset(0); setSubject('') }} />}
          <select className={`${inputClass} flex-1 min-w-48`} aria-label="Grant subject" value={subject} onChange={e => setSubject(e.target.value)}><option value="">Choose {grantLabels[kind].toLowerCase()}…</option>{choices.map(value => <option key={value} value={value}>{kind === 'user' ? userNames.get(value) : kind === 'local_group' ? groupNames.get(value) : value}</option>)}</select>
        </>}
        <button type="button" onClick={addGrant} disabled={!subject || saveGrants.isPending} className="bg-accent text-white rounded px-3 text-sm disabled:opacity-50">Add</button>
      </div>
      {kind === 'user' && <Pagination offset={userOffset} total={usersQuery.data?.total ?? 0} onChange={offset => { setUserOffset(offset); setSubject('') }} />}
      {kind === 'local_group' && <Pagination offset={groupOffset} total={groupsQuery.data?.total ?? 0} onChange={offset => { setGroupOffset(offset); setSubject('') }} />}
      {kind === 'directory_group' && <p className="text-[11px] text-text-faint mt-2">Choose a group by name. Veyport saves its stable directory identity so renamed groups do not silently change access.</p>}
      {kind === 'directory_group' && directoryQuery.isError && <div className="mt-2"><ErrorBox message={directoryQuery.error instanceof Error ? directoryQuery.error.message : 'Could not search directory groups. Add a narrower search.'} /></div>}
      {saveGrants.isError && <div className="mt-3"><ErrorBox message={saveGrants.error instanceof Error ? saveGrants.error.message : 'Could not update access rules.'} /></div>}
      <div className="mt-4 border border-border rounded divide-y divide-border">
        {current.length === 0 && <p className="p-4 text-sm text-text-muted">No application access rules have been added yet.</p>}
        {current.map(entry => <div key={`${entry.kind}:${entry.subject_id}`} className="flex items-center gap-3 px-3 py-2 text-sm"><span className="text-text-muted w-32">{grantLabels[entry.kind]}</span><span className="flex-1 text-text-primary break-all">{entry.kind === 'user' ? userNames.get(entry.subject_id) ?? entry.subject_id : entry.kind === 'local_group' ? groupNames.get(entry.subject_id) ?? entry.subject_id : entry.kind === 'directory_group' ? directoryNames.get(entry.subject_id) ?? entry.subject_id : entry.subject_id}</span><button type="button" disabled={saveGrants.isPending} onClick={() => removeGrant(entry)} className="text-xs text-status-error hover:underline">Remove</button></div>)}
      </div>
    </>}
    <div className="flex justify-end mt-4"><button type="button" onClick={onClose} className="border border-border rounded px-3 py-2 text-sm">Done</button></div>
  </div></div>
}

function AdminApplications() {
  const [offset, setOffset] = useState(0)
  const [editing, setEditing] = useState<ApplicationConfig | null | undefined>(undefined)
  const [granting, setGranting] = useState<ApplicationConfig | null>(null)
  const { data, isLoading, isError, error } = useAdminApplications(offset)
  const { remove } = useApplicationMutations()
  const apps = data?.applications ?? []
  return <>
    <div className="flex items-end justify-between gap-4 mb-5"><div><h1 className="text-xl font-semibold text-text-primary">Manage applications</h1><p className="mt-1 text-sm text-text-muted">Set where applications run and who can use them.</p></div><button type="button" onClick={() => setEditing(null)} className="bg-accent text-white rounded px-3 py-2 text-sm flex items-center gap-2"><Plus className="w-4 h-4" />Add application</button></div>
    <div className="bg-surface border border-border rounded overflow-hidden">
      {isLoading && <p className="p-4 text-sm text-text-muted">Loading applications…</p>}
      {isError && <div className="p-4"><ErrorBox message={error instanceof Error ? error.message : 'Could not load applications.'} /></div>}
      {!isLoading && !isError && apps.length === 0 && <p className="p-6 text-sm text-text-muted text-center">No applications configured.</p>}
      {apps.map(app => <article key={app.id} className="border-b last:border-b-0 border-border px-4 py-3 flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-56"><div className="font-medium text-text-primary">{app.name}</div><div className="text-xs text-text-muted mt-1">{app.public_hostname} · {app.route === 'node' ? 'Connected node' : 'Veyport hub'} · {app.enabled ? 'Enabled' : 'Disabled'}</div></div>
        <button type="button" onClick={() => setGranting(app)} className="text-xs border border-border rounded px-3 py-2 hover:bg-elevated">Access</button>
        <button type="button" onClick={() => setEditing(app)} className="text-xs border border-border rounded px-3 py-2 hover:bg-elevated">Edit</button>
        <button type="button" aria-label={`Delete ${app.name}`} disabled={remove.isPending} onClick={() => { if (window.confirm(`Delete ${app.name}? This ends its active application sessions.`)) remove.mutate(app.id) }} className="text-status-error p-2 disabled:opacity-50"><Trash2 className="w-4 h-4" /></button>
      </article>)}
      {remove.isError && <div className="p-3"><ErrorBox message={remove.error instanceof Error ? remove.error.message : 'Could not delete application.'} /></div>}
    </div>
    <Pagination offset={offset} total={data?.total ?? 0} onChange={setOffset} />
    {editing !== undefined && <ApplicationEditor app={editing ?? undefined} onClose={() => setEditing(undefined)} />}
    {granting && <GrantEditor app={granting} onClose={() => setGranting(null)} />}
  </>
}

function UserPicker({ selected, onChange }: Readonly<{ selected: string[]; onChange: (value: string[]) => void }>) {
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const users = useApplicationUserSubjects(offset, search)
  const current = new Set(selected)
  return <div className="border border-border rounded">
    <div className="p-2 border-b border-border"><input aria-label="Search people" className={inputClass} placeholder="Search by name" value={search} onChange={e => { setSearch(e.target.value); setOffset(0) }} /></div>
    {users.isLoading && <p className="p-3 text-xs text-text-muted">Loading people…</p>}
    {users.isError && <div className="p-3"><ErrorBox message={users.error instanceof Error ? users.error.message : 'Could not load people.'} /></div>}
    {!users.isLoading && !users.isError && users.data?.users.length === 0 && <p className="p-3 text-xs text-text-muted">No people match this search.</p>}
    {(users.data?.users ?? []).map(user => <label key={user.id} className="flex gap-2 px-3 py-2 border-b last:border-b-0 border-border text-sm text-text-secondary"><input type="checkbox" checked={current.has(user.id)} onChange={e => { const next = new Set(current); if (e.target.checked) next.add(user.id); else next.delete(user.id); onChange([...next]) }} /><span>{user.username}</span></label>)}
    <div className="px-3"><Pagination offset={offset} total={users.data?.total ?? 0} onChange={setOffset} /></div>
  </div>
}

function GroupEditor({ group, onClose }: Readonly<{ group?: ApplicationGroup; onClose: () => void }>) {
  const [name, setName] = useState(group?.name ?? '')
  const [userIds, setUserIds] = useState(group?.user_ids ?? [])
  const { createGroup, updateGroup } = useApplicationMutations()
  const mutation = group ? updateGroup : createGroup
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (group) updateGroup.mutate({ id: group.id, name, userIds, expectedVersion: group.version }, { onSuccess: onClose })
    else createGroup.mutate(name, { onSuccess: onClose })
  }
  return <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center overflow-y-auto p-4"><form onSubmit={submit} className="bg-surface border border-border rounded w-full max-w-xl p-5 space-y-4 my-6" aria-label={group ? 'Edit application group' : 'Create application group'}>
    <h2 className="text-lg font-semibold">{group ? 'Edit application group' : 'Create application group'}</h2>
    {mutation.isError && <ErrorBox message={mutation.error instanceof Error ? mutation.error.message : 'Could not save group.'} />}
    <div><label className={labelClass} htmlFor="group-name">Group name</label><input id="group-name" className={inputClass} required maxLength={120} value={name} onChange={e => setName(e.target.value)} /></div>
    {group && <div><label className={labelClass}>People in this group ({userIds.length})</label><UserPicker selected={userIds} onChange={setUserIds} /></div>}
    {!group && <p className="text-xs text-text-muted">You can add people after creating the group.</p>}
    <div className="flex justify-end gap-2"><button type="button" onClick={onClose} className="border border-border rounded px-3 py-2 text-sm">Cancel</button><button type="submit" disabled={mutation.isPending} className="bg-accent text-white rounded px-4 py-2 text-sm">{mutation.isPending ? 'Saving…' : group ? 'Save group' : 'Create group'}</button></div>
  </form></div>
}

function ApplicationGroups() {
  const [offset, setOffset] = useState(0)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const { data, isLoading, isError, error } = useApplicationGroups(offset)
  const groupQuery = useApplicationGroup(editingId)
  const { deleteGroup } = useApplicationMutations()
  return <>
    <div className="flex items-end justify-between gap-4 mb-5"><div><h1 className="text-xl font-semibold text-text-primary">Application groups</h1><p className="mt-1 text-sm text-text-muted">Create groups that are used only to grant application access.</p></div><button type="button" onClick={() => setCreating(true)} className="bg-accent text-white rounded px-3 py-2 text-sm flex items-center gap-2"><Plus className="w-4 h-4" />New group</button></div>
    <div className="bg-surface border border-border rounded overflow-hidden">
      {isLoading && <p className="p-4 text-sm text-text-muted">Loading groups…</p>}
      {isError && <div className="p-4"><ErrorBox message={error instanceof Error ? error.message : 'Could not load groups.'} /></div>}
      {!isLoading && !isError && (data?.groups.length ?? 0) === 0 && <p className="p-6 text-sm text-text-muted text-center">No application groups yet.</p>}
      {(data?.groups ?? []).map(group => <div key={group.id} className="flex items-center gap-3 p-4 border-b last:border-b-0 border-border"><div className="flex-1"><div className="text-sm font-medium text-text-primary">{group.name}</div><div className="text-xs text-text-muted">{group.member_count === undefined ? 'Membership count unavailable' : `${group.member_count} people`}</div></div><button type="button" onClick={() => setEditingId(group.id)} className="text-xs border border-border rounded px-3 py-2">Edit members</button><button type="button" aria-label={`Delete ${group.name}`} onClick={() => { if (window.confirm(`Delete the ${group.name} application group?`)) deleteGroup.mutate(group.id) }} className="text-status-error p-2"><Trash2 className="w-4 h-4" /></button></div>)}
      {deleteGroup.isError && <div className="p-3"><ErrorBox message={deleteGroup.error instanceof Error ? deleteGroup.error.message : 'Could not delete group.'} /></div>}
    </div>
    <Pagination offset={offset} total={data?.total ?? 0} onChange={setOffset} />
    {creating && <GroupEditor onClose={() => setCreating(false)} />}
    {editingId && groupQuery.data && <GroupEditor group={groupQuery.data} onClose={() => setEditingId(null)} />}
    {editingId && groupQuery.isError && <div className="mt-3"><ErrorBox message={groupQuery.error instanceof Error ? groupQuery.error.message : 'Could not load group details.'} /></div>}
  </>
}

function AccessPolicy() {
  const { data, isLoading, isError, error } = useApplicationSettings()
  const { saveSettings } = useApplicationMutations()
  const [form, setForm] = useState<ApplicationSettings | null>(null)
  const current = form ?? data
  if (isLoading) return <p className="text-sm text-text-muted">Loading application session policy…</p>
  if (isError || !data) return <ErrorBox message={error instanceof Error ? error.message : 'Could not load application session policy.'} />
  return <div className="max-w-2xl"><h1 className="text-xl font-semibold text-text-primary">Application session policy</h1><p className="text-sm text-text-muted mt-1 mb-5">Application sessions end after inactivity or when their maximum lifetime is reached. Portal sign-in sessions use separate limits.</p>
    <form className="bg-surface border border-border rounded p-4 space-y-4" onSubmit={e => { e.preventDefault(); if (current) saveSettings.mutate(current, { onSuccess: () => setForm(null) }) }}>
      {saveSettings.isError && <ErrorBox message={saveSettings.error instanceof Error ? saveSettings.error.message : 'Could not save policy.'} />}
      <div><label className={labelClass} htmlFor="app-idle">End after inactivity (minutes)</label><input id="app-idle" type="number" min={1} max={Math.floor((current?.max_seconds ?? 43200) / 60)} required className={inputClass} value={Math.floor((current?.idle_seconds ?? 2700) / 60)} onChange={e => setForm({ ...current!, idle_seconds: Number(e.target.value) * 60 })} /><p className="text-[11px] text-text-faint mt-1">A request to the application counts as activity.</p></div>
      <div><label className={labelClass} htmlFor="app-max">Maximum session length (hours)</label><input id="app-max" type="number" min={1} max={24} required className={inputClass} value={Math.floor((current?.max_seconds ?? 43200) / 3600)} onChange={e => setForm({ ...current!, max_seconds: Number(e.target.value) * 3600 })} /><p className="text-[11px] text-text-faint mt-1">Signing in again does not extend an existing application session.</p></div>
      <div className="flex justify-end"><button type="submit" disabled={saveSettings.isPending || !current} className="bg-accent text-white rounded px-4 py-2 text-sm">{saveSettings.isPending ? 'Saving…' : 'Save policy'}</button></div>
      {saveSettings.isSuccess && <p role="status" className="text-xs text-status-online">Application session policy saved.</p>}
    </form>
  </div>
}

export function ApplicationsPage() {
  const { user } = useAuth()
  const canAdmin = hasCapability(user, 'operations.admin')
  const [panel, setPanel] = useState<Panel>('available')
  const panels: Array<{ id: Panel; title: string }> = [
    { id: 'available', title: 'Available to me' },
    ...(canAdmin ? [{ id: 'applications' as const, title: 'Manage applications' }, { id: 'groups' as const, title: 'Application groups' }, { id: 'policy' as const, title: 'Session policy' }] : []),
  ]
  return <div className="h-full overflow-y-auto p-5 md:p-8">
    <div className="flex flex-wrap gap-2 border-b border-border mb-6" role="tablist" aria-label="Application sections">
      {panels.map(item => <button key={item.id} type="button" role="tab" aria-selected={panel === item.id} onClick={() => setPanel(item.id)} className={`px-3 py-2 text-sm border-b-2 -mb-px ${panel === item.id ? 'border-accent text-text-primary' : 'border-transparent text-text-muted hover:text-text-primary'}`}>{item.title}</button>)}
    </div>
    {panel === 'available' && <AvailableApplications />}
    {panel === 'applications' && canAdmin && <AdminApplications />}
    {panel === 'groups' && canAdmin && <ApplicationGroups />}
    {panel === 'policy' && canAdmin && <AccessPolicy />}
  </div>
}
