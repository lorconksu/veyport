import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApplicationsPage } from '@/pages/applications'
import { apiFetch } from '@/lib/api'

const auth = vi.hoisted(() => ({ user: { id: 'admin-1', username: 'admin', role: 'admin', capabilities: ['operations.admin'] } as { id: string; username: string; role: 'admin'; capabilities?: string[] } | null }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: auth.user }) }))
vi.mock('@/lib/api', () => ({ apiFetch: vi.fn() }))

const mockedFetch = vi.mocked(apiFetch)

function mount() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><ApplicationsPage /></MemoryRouter></QueryClientProvider>)
}

describe('Applications page', () => {
  beforeEach(() => {
    auth.user = { id: 'admin-1', username: 'admin', role: 'admin', capabilities: ['operations.admin'] }
    mockedFetch.mockReset()
  })

  it('shows authorized apps and links to the fixed launch route in a new tab', async () => {
    mockedFetch.mockResolvedValue({ applications: [{ id: 'app-7', name: 'Grafana', description: 'Metrics', public_url: 'https://grafana.apps.example.test', available: true }], total: 1 })
    mount()
    const link = await screen.findByRole('link', { name: /open application/i })
    expect(link).toHaveAttribute('href', '/applications/app-7/launch')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    expect(link).not.toHaveAttribute('href', expect.stringContaining('return='))
  })


  it('paginates authorized applications in non-overlapping 50-entry pages', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) {
        const offset = Number(new URLSearchParams(path.split('?')[1]).get('offset'))
        return { applications: Array.from({ length: 50 }, (_, index) => ({ id: `app-${offset + index}`, name: `Tool ${offset + index}`, description: '', public_url: '', available: true })), total: 100 }
      }
      if (path.startsWith('/auth/application-sessions?')) return { sessions: [], total: 0 }
      return { status: 'ok' }
    })
    mount()
    expect(await screen.findByText('Tool 0')).toBeInTheDocument()
    expect(screen.getByText('1–50 of 100')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Next' })[0])
    expect(await screen.findByText('Tool 50')).toBeInTheDocument()
    expect(screen.queryByText('Tool 0')).not.toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Previous' })[0])
    expect(await screen.findByText('Tool 0')).toBeInTheDocument()
    expect(mockedFetch).toHaveBeenCalledWith('/applications?limit=50&offset=50')
  })


  it('refreshes both lists and identifies an ended legacy session without showing revoke', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [{ id: 'app-a', name: 'Tools', description: '', public_url: '', available: true }], total: 1 }
      if (path.startsWith('/auth/application-sessions?')) return { sessions: [{ id: 'old-session', application_id: 'retired-app', created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-02T00:00:00Z', ended_at: '2026-01-01T01:00:00Z', end_reason: 'expired_idle' }], total: 1 }
      return { status: 'ok' }
    })
    mount()
    const sessions = screen.getByText('Your application sessions').closest('section')!
    expect(await within(sessions).findByText('Application retired-app')).toBeInTheDocument()
    expect(within(sessions).getByText('Ended: expired idle')).toBeInTheDocument()
    expect(within(sessions).queryByRole('button', { name: 'End session' })).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: 'Refresh' }))
    fireEvent.click(within(sessions).getByRole('button', { name: 'Refresh application sessions' }))
    await waitFor(() => expect(mockedFetch.mock.calls.filter(([path]) => path.startsWith('/applications?')).length).toBeGreaterThan(1))
    await waitFor(() => expect(mockedFetch.mock.calls.filter(([path]) => path.startsWith('/auth/application-sessions?')).length).toBeGreaterThan(1))
  })

  it('shows session load and revoke failures without hiding the rest of the page', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/auth/application-sessions?')) {
        if (mockedFetch.mock.calls.filter(([p]) => p.startsWith('/auth/application-sessions?')).length === 1) throw new Error('Session history unavailable')
        return { sessions: [{ id: 'live-session', application_id: 'app-live', created_at: '', last_seen_at: '', expires_at: '2026-01-02T00:00:00Z' }], total: 1 }
      }
      if (path === '/auth/application-sessions/live-session' && options?.method === 'DELETE') throw new Error('Revocation failed')
      return { status: 'ok' }
    })
    mount()
    const sessions = screen.getByText('Your application sessions').closest('section')!
    expect(await within(sessions).findByRole('alert')).toHaveTextContent('Session history unavailable')
    fireEvent.click(within(sessions).getByRole('button', { name: 'Refresh application sessions' }))
    fireEvent.click(await within(sessions).findByRole('button', { name: 'End session' }))
    expect(await within(sessions).findByRole('alert')).toHaveTextContent('Revocation failed')
    confirm.mockRestore()
  })

  it('paginates all application sessions and can revoke an older page entry', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/auth/application-sessions?')) {
        const offset = Number(new URLSearchParams(path.split('?')[1]).get('offset'))
        return { sessions: Array.from({ length: Math.min(50, 101 - offset) }, (_, index) => {
          const id = offset + index
          return { id: `session-${id}`, application_id: 'app-1', application_name: 'Wiki', created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-02T00:00:00Z' }
        }), total: 101 }
      }
      if (path === '/auth/application-sessions/session-100' && options?.method === 'DELETE') return { status: 'ended' }
      return { status: 'ok' }
    })
    mount()
    const sessions = screen.getByText('Your application sessions').closest('section')!
    expect(await within(sessions).findByText('1–50 of 101')).toBeInTheDocument()
    fireEvent.click(within(sessions).getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/auth/application-sessions?limit=50&offset=50'))
    expect(await within(sessions).findByText('51–100 of 101')).toBeInTheDocument()
    fireEvent.click(within(sessions).getByRole('button', { name: 'Next' }))
    expect(await within(sessions).findAllByText('Wiki')).toHaveLength(1)
    expect(mockedFetch).toHaveBeenCalledWith('/auth/application-sessions?limit=50&offset=100')
    fireEvent.click(within(sessions).getByRole('button', { name: 'End session' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/auth/application-sessions/session-100', expect.objectContaining({ method: 'DELETE' })))
    confirm.mockRestore()
  })

  it('does not infer a zero application-group membership count from the bounded list DTO', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-1', name: 'Editors', user_ids: [], member_count: 4, version: 1 }], total: 1 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    expect(await screen.findByText('4 people')).toBeInTheDocument()
  })

  it('keeps an unavailable node app from opening and does not expose its backend URL', async () => {
    mockedFetch.mockResolvedValue({ applications: [{ id: 'app-node', name: 'Build tools', description: '', public_url: 'https://build.apps.test', available: false, availability_reason: 'The connected node is offline' }], total: 1 })
    mount()
    const link = await screen.findByRole('link', { name: /open application/i })
    expect(link).toHaveAttribute('aria-disabled', 'true')
    expect(link).toHaveAttribute('href', '/applications/app-node/launch')
    expect(link).not.toHaveAttribute('href', 'https://build.apps.test')
    expect(await screen.findByText(/connected node is offline/i)).toBeInTheDocument()
    expect(fireEvent.click(link)).toBe(false)
  })

  it('hides management panels without the operations capability', async () => {
    auth.user = { id: 'user-1', username: 'reader', role: 'admin', capabilities: [] }
    mockedFetch.mockResolvedValue({ applications: [], total: 0 })
    mount()
    expect(await screen.findByText(/no applications are available/i)).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /manage applications/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /application groups/i })).not.toBeInTheDocument()
  })

  it('creates an application with bounded address inputs and allowed ranges', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [], total: 0, limit: 50, offset: 0 }
      if (path === '/admin/applications' && options?.method === 'POST') return { id: 'new-app' }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(screen.getByRole('button', { name: /add application/i }))
    const dialog = screen.getByRole('form', { name: 'Add application' })
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Internal wiki' } })
    fireEvent.change(within(dialog).getByLabelText('Short name'), { target: { value: 'wiki' } })
    fireEvent.change(within(dialog).getByLabelText('Application address'), { target: { value: 'https://wiki.internal:8443' } })
    fireEvent.change(within(dialog).getByLabelText('Allowed network ranges'), { target: { value: '10.8.0.0/16\nfd00:8::/64' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create application' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/applications', expect.objectContaining({ method: 'POST' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/applications' && opts?.method === 'POST')!
    expect(JSON.parse(String(request?.body))).toMatchObject({ name: 'Internal wiki', slug: 'wiki', route: 'hub', backend_url: 'https://wiki.internal:8443', allowed_cidrs: ['10.8.0.0/16', 'fd00:8::/64'] })
  })

  it('marks required fields and toggles field help with click and keyboard without submitting', async () => {
    const user = userEvent.setup()
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [], total: 0, limit: 50, offset: 0 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(screen.getByRole('button', { name: /add application/i }))
    const form = screen.getByRole('form', { name: 'Add application' })
    expect(within(form).getByText('Required field')).toBeInTheDocument()
    for (const label of ['Name', 'Short name', 'Connect through', 'Application address', 'Allowed network ranges']) {
      expect(within(form).getByLabelText(label)).toBeRequired()
      expect(within(form).getByLabelText(label).getAttribute('aria-describedby')).toBeTruthy()
    }
    expect(within(form).queryByLabelText('Connected node')).not.toBeInTheDocument()

    await user.click(within(form).getByRole('button', { name: 'Help for Short name' }))
    expect(within(form).getByText(/1–63 lowercase letters, digits, or hyphens/i)).toBeVisible()
    expect(within(form).getByRole('button', { name: 'Help for Short name' })).toHaveAttribute('aria-expanded', 'true')

    const nameHelp = within(form).getByRole('button', { name: 'Help for Name' })
    nameHelp.focus()
    await user.keyboard('{Enter}')
    expect(nameHelp).toHaveAttribute('aria-expanded', 'true')
    await user.keyboard(' ')
    expect(nameHelp).toHaveAttribute('aria-expanded', 'false')

    fireEvent.change(within(form).getByLabelText('Connect through'), { target: { value: 'node' } })
    expect(within(form).getByLabelText('Connected node')).toBeRequired()
    expect(within(form).queryByRole('button', { name: 'Create application' })).toBeInTheDocument()
    expect(mockedFetch).not.toHaveBeenCalledWith('/admin/applications', expect.objectContaining({ method: 'POST' }))
  })


  it('updates an existing node-routed application with optimistic config version', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-edit', name: 'Wiki', slug: 'wiki', description: 'Docs', public_hostname: 'wiki.apps.test', route: 'hub', node_id: '', backend_url: 'https://wiki.internal', allowed_cidrs: ['10.0.0.0/8'], enabled: true, config_version: 8, created_at: '', updated_at: '' }], total: 1 }
      if (path.startsWith('/servers?')) return { servers: [{ id: 'node-1', name: 'web-1', status: 'online' }], total: 1 }
      if (path === '/admin/applications/app-edit' && options?.method === 'PUT') return { id: 'app-edit' }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    const editor = screen.getByRole('form', { name: 'Edit application' })
    fireEvent.change(within(editor).getByLabelText('Name'), { target: { value: 'Wiki updated' } })
    fireEvent.change(within(editor).getByLabelText('Connect through'), { target: { value: 'node' } })
    const nodeChoice = await within(editor).findByRole('option', { name: 'web-1 · online' })
    fireEvent.change(within(editor).getByLabelText('Connected node'), { target: { value: nodeChoice.getAttribute('value') } })
    fireEvent.click(within(editor).getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/applications/app-edit', expect.objectContaining({ method: 'PUT' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/applications/app-edit' && opts?.method === 'PUT')!
    expect(JSON.parse(String(request?.body))).toMatchObject({ name: 'Wiki updated', route: 'node', node_id: 'node-1', expected_version: 8 })
  })

  it('loads omitted optional application fields as empty values and keeps an edit open on failure', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-partial', name: 'Partial config', slug: 'partial', description: '', public_hostname: 'partial.apps.test', route: 'hub', backend_url: 'https://partial.internal', enabled: false, config_version: 2, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications/app-partial' && options?.method === 'PUT') throw new Error('Address is not allowed')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('form', { name: 'Edit application' })
    expect(within(form).getByLabelText('Allowed network ranges')).toHaveValue('')
    expect(within(form).getByLabelText('Private certificate authority (optional)')).toHaveValue('')
    expect(within(form).getByLabelText('Application is enabled')).not.toBeChecked()
    fireEvent.change(within(form).getByLabelText('Description'), { target: { value: 'Private docs' } })
    fireEvent.change(within(form).getByLabelText('Allowed network ranges'), { target: { value: '10.1.0.0/16' } })
    fireEvent.click(within(form).getByLabelText('Application is enabled'))
    fireEvent.click(within(form).getByRole('button', { name: 'Save changes' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('Address is not allowed')
    expect(screen.getByRole('form', { name: 'Edit application' })).toBeInTheDocument()
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/applications/app-partial' && opts?.method === 'PUT')!
    expect(JSON.parse(String(request?.body))).toMatchObject({ description: 'Private docs', allowed_cidrs: ['10.1.0.0/16'], ca_pem: '', enabled: true, expected_version: 2 })
  })

  it('creates and deletes a local application group with confirmations', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-new', name: 'Editors', user_ids: [], member_count: 0, version: 1 }], total: 1 }
      if (path === '/admin/application-groups' && options?.method === 'POST') return { id: 'group-new' }
      if (path === '/admin/application-groups/group-new' && options?.method === 'DELETE') return { status: 'deleted' }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(screen.getByRole('button', { name: 'New group' }))
    const form = screen.getByRole('form', { name: 'Create application group' })
    fireEvent.change(within(form).getByLabelText('Group name'), { target: { value: 'Editors' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Create group' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/application-groups', expect.objectContaining({ method: 'POST' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/application-groups' && opts?.method === 'POST')!
    expect(JSON.parse(String(request?.body))).toEqual({ name: 'Editors' })
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Editors' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/application-groups/group-new', expect.objectContaining({ method: 'DELETE' })))
    confirm.mockRestore()
  })

  it('edits application-group membership using the group version and sends the selected people', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-1', name: 'Editors', user_ids: ['user-1'], version: 4 }], total: 1 }
      if (path === '/admin/application-groups/group-1' && options?.method === 'PUT') return { status: 'ok' }
      if (path === '/admin/application-groups/group-1') return { id: 'group-1', name: 'Editors', user_ids: ['user-1'], version: 4 }
      if (path.startsWith('/admin/application-subjects/users?')) return { users: [{ id: 'user-1', username: 'one' }, { id: 'user-2', username: 'two' }], total: 2 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit members' }))
    const dialog = await screen.findByRole('form', { name: 'Edit application group' })
    fireEvent.click(await within(dialog).findByLabelText('two'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save group' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/application-groups/group-1', expect.objectContaining({ method: 'PUT' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/application-groups/group-1' && opts?.method === 'PUT')!
    expect(JSON.parse(String(request?.body))).toMatchObject({ name: 'Editors', user_ids: ['user-1', 'user-2'], expected_version: 4 })
  })

  it('shows directory-user lookup errors while editing a group', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-offline', name: 'Reviewers', user_ids: [], version: 1 }], total: 1 }
      if (path === '/admin/application-groups/group-offline') return { id: 'group-offline', name: 'Reviewers', user_ids: [], version: 1 }
      if (path.startsWith('/admin/application-subjects/users?')) throw new Error('People lookup is unavailable')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit members' }))
    const form = await screen.findByRole('form', { name: 'Edit application group' })
    expect(await within(form).findByRole('alert')).toHaveTextContent('People lookup is unavailable')
  })

  it('keeps a group edit available after a versioned membership update is rejected', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-stale', name: 'Reviewers', user_ids: [], member_count: 0, version: 4 }], total: 1 }
      if (path === '/admin/application-groups/group-stale' && options?.method === 'PUT') throw new Error('Group changed; reload before saving')
      if (path === '/admin/application-groups/group-stale') return { id: 'group-stale', name: 'Reviewers', user_ids: [], version: 4 }
      if (path.startsWith('/admin/application-subjects/users?')) return { users: [], total: 0 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit members' }))
    const form = await screen.findByRole('form', { name: 'Edit application group' })
    fireEvent.change(within(form).getByLabelText('Group name'), { target: { value: 'Reviewers updated' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Save group' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('Group changed; reload before saving')
    expect(screen.getByRole('form', { name: 'Edit application group' })).toBeInTheDocument()
  })

  it('fetches the next bounded user page when editing local-group membership', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-2', name: 'Reviewers', user_ids: [], version: 1 }], total: 1 }
      if (path === '/admin/application-groups/group-2') return { id: 'group-2', name: 'Reviewers', user_ids: [], version: 1 }
      if (path.startsWith('/admin/application-subjects/users?')) {
        const offset = Number(new URLSearchParams(path.split('?')[1]).get('offset'))
        const users = offset === 50 ? [{ id: 'person-50', username: 'person-50' }] : Array.from({ length: 50 }, (_, index) => ({ id: `person-${index}`, username: `person-${index}` }))
        return { users, total: 51 }
      }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit members' }))
    const dialog = await screen.findByRole('form', { name: 'Edit application group' })
    expect(await within(dialog).findByLabelText('person-0')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Next' }))
    expect(await within(dialog).findByLabelText('person-50')).toBeInTheDocument()
    expect(mockedFetch).toHaveBeenCalledWith('/admin/application-subjects/users?limit=50&offset=50')
  })

  it('saves separate application session limits with the current settings version', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path === '/admin/application-settings' && options?.method === 'PUT') return { idle_seconds: 3600, max_seconds: 86400, version: 3 }
      if (path === '/admin/application-settings') return { idle_seconds: 2700, max_seconds: 43200, version: 2 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Session policy' }))
    fireEvent.change(await screen.findByLabelText('End after inactivity (minutes)'), { target: { value: '60' } })
    fireEvent.change(screen.getByLabelText('Maximum session length (hours)'), { target: { value: '24' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/application-settings', expect.objectContaining({ method: 'PUT' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/application-settings' && opts?.method === 'PUT')!
    expect(JSON.parse(String(request?.body))).toEqual({ idle_seconds: 3600, max_seconds: 86400, expected_version: 2 })
  })

  it('reports stale application access edits returned by the server', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-1', name: 'Wiki', slug: 'wiki', description: '', public_hostname: 'wiki.apps.test', route: 'hub', backend_url: 'https://wiki.internal', allowed_cidrs: ['10.0.0.0/8'], enabled: true, config_version: 4, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications/app-1/grants' && options?.method === 'PUT') throw Object.assign(new Error('application changed; reload before saving'), { status: 409 })
      if (path === '/admin/applications/app-1/grants') return { grants: [], config_version: 4 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Access' }))
    const dialog = await screen.findByRole('dialog', { name: 'Access for Wiki' })
    fireEvent.change(await within(dialog).findByLabelText('Grant type'), { target: { value: 'role' } })
    fireEvent.change(await within(dialog).findByLabelText('Grant subject'), { target: { value: 'viewer' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('application changed; reload before saving')
  })

  it('stores the directory group stable ID returned by the subject picker', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-2', name: 'Payroll', slug: 'payroll', description: '', public_hostname: 'payroll.apps.test', route: 'hub', backend_url: 'https://payroll.internal', allowed_cidrs: ['10.0.0.0/8'], enabled: true, config_version: 6, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications/app-2/grants' && options?.method === 'PUT') return { grants: [{ kind: 'directory_group', subject_id: 'ldap:group-uuid' }], config_version: 7 }
      if (path === '/admin/applications/app-2/grants') return { grants: [], config_version: 6 }
      if (path.startsWith('/admin/application-subjects/directory-groups?')) return { groups: [{ subject_id: 'ldap:group-uuid', name: 'Finance' }], total: 1 }
      if (path.startsWith('/admin/application-subjects/users?')) return { users: [], total: 0 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Access' }))
    const dialog = await screen.findByRole('dialog', { name: 'Access for Payroll' })
    fireEvent.change(await within(dialog).findByLabelText('Grant type'), { target: { value: 'directory_group' } })
    expect(await within(dialog).findByRole('option', { name: 'Finance' })) .toHaveValue('ldap:group-uuid')
    fireEvent.change(within(dialog).getByLabelText('Directory group'), { target: { value: 'ldap:group-uuid' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/applications/app-2/grants', expect.objectContaining({ method: 'PUT' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/applications/app-2/grants' && opts?.method === 'PUT')!
    expect(JSON.parse(String(request?.body))).toMatchObject({ grants: [{ kind: 'directory_group', subject_id: 'ldap:group-uuid' }], expected_version: 6 })
    expect(mockedFetch).not.toHaveBeenCalledWith(expect.stringContaining('/application-subjects/users?'), expect.anything())
  })

  it('adds a person grant using the selected username and stable user ID', async () => {
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-person', name: 'Reports', slug: 'reports', description: '', public_hostname: 'reports.apps.test', route: 'hub', backend_url: 'https://reports.internal', allowed_cidrs: [], enabled: true, config_version: 2, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications/app-person/grants' && options?.method === 'PUT') return { grants: [{ kind: 'user', subject_id: 'user-2' }], config_version: 3 }
      if (path === '/admin/applications/app-person/grants') return { grants: [], config_version: 2 }
      if (path.startsWith('/admin/application-subjects/users?')) return { users: [{ id: 'user-2', username: 'jane' }], total: 1 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Access' }))
    const dialog = await screen.findByRole('dialog', { name: 'Access for Reports' })
    fireEvent.change(await within(dialog).findByLabelText('Search people for grant'), { target: { value: 'jane' } })
    expect(await within(dialog).findByRole('option', { name: 'jane (user-2)' })).toHaveValue('user-2')
    fireEvent.change(within(dialog).getByLabelText('Grant subject'), { target: { value: 'user-2' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/applications/app-person/grants', expect.objectContaining({ method: 'PUT' })))
    const [, request] = mockedFetch.mock.calls.find(([path, opts]) => path === '/admin/applications/app-person/grants' && opts?.method === 'PUT')!
    expect(JSON.parse(String(request?.body))).toMatchObject({ grants: [{ kind: 'user', subject_id: 'user-2' }], expected_version: 2 })
  })

  it('keeps the access editor open and reports an access-rule loading error', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-no-grants', name: 'Reports', slug: 'reports', description: '', public_hostname: 'reports.apps.test', route: 'hub', backend_url: 'https://reports.internal', allowed_cidrs: [], enabled: true, config_version: 2, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications/app-no-grants/grants') throw new Error('Access rules could not be loaded')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Access' }))
    expect(await screen.findByRole('dialog', { name: 'Access for Reports' })).toBeInTheDocument()
    expect(await screen.findByRole('alert')).toHaveTextContent('Access rules could not be loaded')
    expect(screen.queryByLabelText('Grant type')).not.toBeInTheDocument()
  })


  it('asks before removing an access grant that can end active sessions', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    mockedFetch.mockImplementation(async (path) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-1', name: 'Wiki', slug: 'wiki', description: '', public_hostname: 'wiki.apps.test', route: 'hub', backend_url: 'https://wiki.internal', allowed_cidrs: ['10.0.0.0/8'], enabled: true, config_version: 4, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications/app-1/grants') return { grants: [{ kind: 'role', subject_id: 'viewer' }], config_version: 4 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Access' }))
    const dialog = await screen.findByRole('dialog', { name: 'Access for Wiki' })
    fireEvent.click(await within(dialog).findByRole('button', { name: 'Remove' }))
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('active application sessions ended'))
    expect(mockedFetch).not.toHaveBeenCalledWith('/admin/applications/app-1/grants', expect.objectContaining({ method: 'PUT' }))
    confirm.mockRestore()
  })

  it('shows API errors instead of presenting an empty application list', async () => {
    mockedFetch.mockRejectedValue(new Error('Access service is unavailable'))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('Access service is unavailable')
    expect(screen.queryByText(/no applications are available/i)).not.toBeInTheDocument()
  })

  it('reports application creation and deletion failures in their forms', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-delete', name: 'Legacy wiki', slug: 'legacy', description: '', public_hostname: 'legacy.apps.test', route: 'hub', backend_url: 'https://legacy.internal', allowed_cidrs: ['10.0.0.0/8'], enabled: true, config_version: 1, created_at: '', updated_at: '' }], total: 1 }
      if (path === '/admin/applications' && options?.method === 'POST') throw new Error('Application could not be created')
      if (path === '/admin/applications/app-delete' && options?.method === 'DELETE') throw new Error('Application still has an active dependency')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add application' }))
    const form = screen.getByRole('form', { name: 'Add application' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'Internal wiki' } })
    fireEvent.change(within(form).getByLabelText('Short name'), { target: { value: 'wiki' } })
    fireEvent.change(within(form).getByLabelText('Application address'), { target: { value: 'https://wiki.internal' } })
    fireEvent.change(within(form).getByLabelText('Allowed network ranges'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Create application' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('Application could not be created')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Legacy wiki' }))
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('ends its active application sessions'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Application still has an active dependency')
    confirm.mockRestore()
  })

  it('reports group list and detail lookup failures', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) throw new Error('Groups are unavailable')
      if (path === '/admin/application-groups/group-detail') throw new Error('Group details are unavailable')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Groups are unavailable')
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-detail', name: 'Editors', user_ids: [], member_count: 0, version: 1 }], total: 1 }
      if (path === '/admin/application-groups/group-detail') throw new Error('Group details are unavailable')
      return { status: 'ok' }
    })
    fireEvent.click(await screen.findByRole('tab', { name: 'Available to me' }))
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit members' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Group details are unavailable')
  })

  it('confirms application-group deletion and leaves a visible error when it fails', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-delete', name: 'Contractors', user_ids: [], member_count: 2, version: 1 }], total: 1 }
      if (path === '/admin/application-groups/group-delete' && options?.method === 'DELETE') throw new Error('Group is still assigned')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Application groups' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Contractors' }))
    expect(mockedFetch).not.toHaveBeenCalledWith('/admin/application-groups/group-delete', expect.objectContaining({ method: 'DELETE' }))
    confirm.mockReturnValue(true)
    fireEvent.click(screen.getByRole('button', { name: 'Delete Contractors' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Group is still assigned')
    confirm.mockRestore()
  })

  it('reports administrative application list failures without treating them as an empty list', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) throw 'admin list unavailable'
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load applications.')
    expect(screen.queryByText('No applications configured.')).not.toBeInTheDocument()
  })

  it('saves and removes local-group grants, with directory search failures shown', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    let saved = false
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path.startsWith('/admin/applications?')) return { applications: [{ id: 'app-grants', name: 'Wiki', slug: 'wiki', description: '', public_hostname: 'wiki.apps.test', route: 'hub', backend_url: 'https://wiki.internal', allowed_cidrs: [], enabled: true, config_version: 3, created_at: '', updated_at: '' }], total: 1 }
      if (path.startsWith('/admin/application-groups?')) return { groups: [{ id: 'group-editors', name: 'Editors', user_ids: [], member_count: 0, version: 1 }], total: 1 }
      if (path === '/admin/applications/app-grants/grants' && options?.method === 'PUT') {
        saved = JSON.parse(String(options.body)).grants.length > 0
        return { grants: saved ? [{ kind: 'local_group', subject_id: 'group-editors' }] : [], config_version: 4 }
      }
      if (path === '/admin/applications/app-grants/grants') return { grants: saved ? [{ kind: 'local_group', subject_id: 'group-editors' }] : [], config_version: 3 }
      if (path.startsWith('/admin/application-subjects/directory-groups?')) throw new Error('Directory search is unavailable')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Manage applications' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Access' }))
    const dialog = await screen.findByRole('dialog', { name: 'Access for Wiki' })
    fireEvent.change(await within(dialog).findByLabelText('Grant type'), { target: { value: 'local_group' } })
    expect(await within(dialog).findByRole('option', { name: /Editors/ })).toBeInTheDocument()
    fireEvent.change(await within(dialog).findByLabelText('Grant subject'), { target: { value: 'group-editors' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(mockedFetch).toHaveBeenCalledWith('/admin/applications/app-grants/grants', expect.objectContaining({ method: 'PUT' })))
    fireEvent.click(await within(dialog).findByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(mockedFetch.mock.calls.filter(([path, options]) => path === '/admin/applications/app-grants/grants' && options?.method === 'PUT')).toHaveLength(2))
    fireEvent.change(within(dialog).getByLabelText('Grant type'), { target: { value: 'directory_group' } })
    fireEvent.change(within(dialog).getByLabelText('Search directory groups'), { target: { value: 'finance' } })
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Directory search is unavailable')
    confirm.mockRestore()
  })

  it('shows application policy load and save failures', async () => {
    let rejectSave = false
    mockedFetch.mockImplementation(async (path, options) => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path === '/admin/application-settings' && options?.method === 'PUT') {
        if (rejectSave) throw new Error('Policy update was rejected')
        return { idle_seconds: 2700, max_seconds: 43200, version: 2 }
      }
      if (path === '/admin/application-settings') return { idle_seconds: 2700, max_seconds: 43200, version: 1 }
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Session policy' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Save policy' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Application session policy saved.')
    fireEvent.change(screen.getByLabelText('End after inactivity (minutes)'), { target: { value: '30' } })
    rejectSave = true
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Policy update was rejected')
  })

  it('shows a policy load error rather than rendering an empty session form', async () => {
    mockedFetch.mockImplementation(async path => {
      if (path.startsWith('/applications?')) return { applications: [], total: 0 }
      if (path === '/admin/application-settings') throw new Error('Session policy is unavailable')
      return { status: 'ok' }
    })
    mount()
    fireEvent.click(await screen.findByRole('tab', { name: 'Session policy' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Session policy is unavailable')
    expect(screen.queryByLabelText('End after inactivity (minutes)')).not.toBeInTheDocument()
  })
})
