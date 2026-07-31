import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DirectoryTab } from '../settings-directory-tab'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

const mockLDAPConfig = {
  enabled: true,
  url: 'ldaps://freeipa.yiucloud.com:636',
  bind_dn: 'uid=veyport,cn=sysaccounts,cn=etc,dc=yiucloud,dc=com',
  bind_password: '',
  bind_password_set: true,
  user_base_dn: 'cn=users,cn=accounts,dc=yiucloud,dc=com',
  group_base_dn: 'cn=groups,cn=accounts,dc=yiucloud,dc=com',
  user_search_filter: '(uid={username})',
  group_search_filter: '(|(member={dn})(memberUid={username}))',
  username_attribute: 'uid',
  email_attribute: 'mail',
  external_id_attribute: 'entryUUID',
  group_name_attribute: 'cn',
  start_tls: false,
  tls_server_name: 'freeipa.yiucloud.com',
  ca_cert_pem: '',
  allow_insecure_transport: false,
  admin_groups: ['freeipa-admins'],
  auditor_groups: ['freeipa-auditors'],
  viewer_groups: ['freeipa-viewers'],
  terminal_groups: ['bastion-users', 'ssh-users'],
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <DirectoryTab />
    </QueryClientProvider>,
  )
}

describe('DirectoryTab', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: RequestInit) => {
      if (url === '/settings/ldap' && !opts?.method) return Promise.resolve(mockLDAPConfig)
      if (url === '/settings/ldap' && opts?.method === 'PUT') return Promise.resolve({ status: 'ok' })
      if (url === '/settings/ldap/test' && opts?.method === 'POST') return Promise.resolve({ status: 'ok' })
      return Promise.resolve({})
    })
  })

  it('loads LDAP config and leaves the bind password blank', async () => {
    renderTab()

    await waitFor(() => {
      expect(screen.getByText('LDAP Directory')).toBeInTheDocument()
      expect(screen.getByLabelText('LDAP URL')).toHaveValue('ldaps://freeipa.yiucloud.com:636')
    })
    expect(screen.getByLabelText('Bind Password')).toHaveValue('')
    expect(screen.getByText('Password is currently stored.')).toBeInTheDocument()
  })

  it('renders configurable role and terminal group mappings', async () => {
    renderTab()

    await waitFor(() => {
      expect(screen.getByLabelText('Admin Groups')).toHaveValue('freeipa-admins')
    })
    expect(screen.getByLabelText('Auditor Groups')).toHaveValue('freeipa-auditors')
    expect(screen.getByLabelText('Viewer Groups')).toHaveValue('freeipa-viewers')
    expect(screen.getByLabelText('Terminal Groups')).toHaveValue('bastion-users, ssh-users')
  })

  it('saves LDAP config with group mappings as arrays', async () => {
    renderTab()
    expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Admin Groups'), {
      target: { value: 'ipa-veyport-admins, security-admins' },
    })
    fireEvent.change(screen.getByLabelText('Bind Password'), {
      target: { value: 'new-bind-secret' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Save LDAP Settings/ }))

    await waitFor(() => {
      const putCall = mockApiFetch.mock.calls.find(call => call[0] === '/settings/ldap' && call[1]?.method === 'PUT')
      expect(putCall).toBeTruthy()
      const body = JSON.parse(putCall![1]!.body as string)
      expect(body.bind_password).toBe('new-bind-secret')
      expect(body.admin_groups).toEqual(['ipa-veyport-admins', 'security-admins'])
      expect(body.terminal_groups).toEqual(['bastion-users', 'ssh-users'])
    })
    await waitFor(() => {
      expect(screen.getByLabelText('Bind Password')).toHaveValue('')
    })
  })

  it('tests the current LDAP form values', async () => {
    renderTab()
    expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))

    await waitFor(() => {
      const testCall = mockApiFetch.mock.calls.find(call => call[0] === '/settings/ldap/test')
      expect(testCall).toBeTruthy()
      expect(testCall![1]?.method).toBe('POST')
    })
    expect(screen.getByText('LDAP connection test passed.')).toBeInTheDocument()
  })

  it('shows save errors', async () => {
    mockApiFetch.mockImplementation((url: string, opts?: RequestInit) => {
      if (url === '/settings/ldap' && !opts?.method) return Promise.resolve(mockLDAPConfig)
      if (url === '/settings/ldap' && opts?.method === 'PUT') return Promise.reject(new Error('secure transport required'))
      return Promise.resolve({})
    })

    renderTab()
    expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Save LDAP Settings/ }))

    await waitFor(() => {
      expect(screen.getByText('secure transport required')).toBeInTheDocument()
    })
  })

  it('shows test connection errors', async () => {
    mockApiFetch.mockImplementation((url: string, opts?: RequestInit) => {
      if (url === '/settings/ldap' && !opts?.method) return Promise.resolve(mockLDAPConfig)
      if (url === '/settings/ldap/test') return Promise.reject(new Error('failed to connect to LDAP'))
      return Promise.resolve({})
    })

    renderTab()
    expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))

    await waitFor(() => {
      expect(screen.getByText('failed to connect to LDAP')).toBeInTheDocument()
    })
  })

  it('shows a fallback message for test errors without a message', async () => {
    mockApiFetch.mockImplementation((url: string, opts?: RequestInit) => {
      if (url === '/settings/ldap' && !opts?.method) return Promise.resolve(mockLDAPConfig)
      if (url === '/settings/ldap/test') return Promise.reject(new Error(''))
      return Promise.resolve({})
    })

    renderTab()
    expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))

    await waitFor(() => {
      expect(screen.getByText('LDAP connection test failed.')).toBeInTheDocument()
    })
  })

  it('clears success feedback after a few seconds', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderTab()
      expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: /Save LDAP Settings/ }))
      expect(await screen.findByText('LDAP configuration saved.')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: /Test Connection/ }))
      expect(await screen.findByText('LDAP connection test passed.')).toBeInTheDocument()

      vi.advanceTimersByTime(3100)
      await waitFor(() => {
        expect(screen.queryByText('LDAP configuration saved.')).not.toBeInTheDocument()
        expect(screen.queryByText('LDAP connection test passed.')).not.toBeInTheDocument()
      })
    } finally {
      vi.useRealTimers()
    }
  })

  it('edits every field and submits the full form', async () => {
    renderTab()
    expect(await screen.findByLabelText('LDAP URL')).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Enable LDAP'))
    fireEvent.click(screen.getByLabelText('Enable LDAP'))
    fireEvent.click(screen.getByLabelText('StartTLS'))
    fireEvent.click(screen.getByLabelText('Allow insecure transport'))

    const textFields: Array<[string, string]> = [
      ['LDAP URL', 'ldap://dir.internal:389'],
      ['Bind DN', 'uid=svc,dc=internal'],
      ['User Base DN', 'ou=people,dc=internal'],
      ['Group Base DN', 'ou=groups,dc=internal'],
      ['Auditor Groups', 'auditors-a, auditors-a, auditors-b'],
      ['Viewer Groups', ''],
      ['Terminal Groups', 'term-users'],
      ['User Search Filter', '(cn={username})'],
      ['Group Search Filter', '(member={dn})'],
      ['Username Attribute', 'cn'],
      ['Email Attribute', 'emailAddress'],
      ['External ID Attribute', 'objectGUID'],
      ['Group Name Attribute', 'name'],
      ['TLS Server Name', 'dir.internal'],
      ['CA Certificate PEM', '-----BEGIN CERTIFICATE-----'],
    ]
    for (const [label, value] of textFields) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } })
    }

    fireEvent.click(screen.getByRole('button', { name: /Save LDAP Settings/ }))

    await waitFor(() => {
      const putCall = mockApiFetch.mock.calls.find(call => call[0] === '/settings/ldap' && call[1]?.method === 'PUT')
      expect(putCall).toBeTruthy()
      const body = JSON.parse(putCall![1]!.body as string)
      expect(body.url).toBe('ldap://dir.internal:389')
      expect(body.start_tls).toBe(true)
      expect(body.allow_insecure_transport).toBe(true)
      // parseGroups trims, de-duplicates, and drops empties
      expect(body.auditor_groups).toEqual(['auditors-a', 'auditors-b'])
      expect(body.viewer_groups).toEqual([])
      expect(body.external_id_attribute).toBe('objectGUID')
      expect(body.ca_cert_pem).toBe('-----BEGIN CERTIFICATE-----')
    })
  })
})
