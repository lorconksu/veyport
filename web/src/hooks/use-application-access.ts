import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import type {
  ApplicationAdminListResponse,
  ApplicationConfigInput,
  ApplicationGrantsResponse,
  ApplicationGroup,
  ApplicationGroupListResponse,
  ApplicationDirectoryGroupsResponse,
  ApplicationListResponse,
  ApplicationSettings,
  ApplicationUserSubjectsResponse,
  ApplicationSessionsResponse,
} from '@/types/application-access'

const APPLICATIONS_KEY = ['applications'] as const
const ADMIN_APPLICATIONS_KEY = ['admin-applications'] as const
const APPLICATION_GROUPS_KEY = ['application-groups'] as const
const APPLICATION_SETTINGS_KEY = ['application-settings'] as const
const APPLICATION_SESSIONS_KEY = ['application-sessions'] as const

export function useAuthorizedApplications(offset = 0) {
  return useQuery({
    queryKey: [...APPLICATIONS_KEY, offset],
    queryFn: () => apiFetch<ApplicationListResponse>(`/applications?limit=50&offset=${offset}`),
  })
}

export function useAdminApplications(offset: number) {
  return useQuery({
    queryKey: [...ADMIN_APPLICATIONS_KEY, offset],
    queryFn: () => apiFetch<ApplicationAdminListResponse>(`/admin/applications?limit=50&offset=${offset}`),
  })
}

export function useApplicationGrants(applicationId: string | null) {
  return useQuery({
    queryKey: [...ADMIN_APPLICATIONS_KEY, applicationId, 'grants'],
    enabled: !!applicationId,
    queryFn: () => apiFetch<ApplicationGrantsResponse>(`/admin/applications/${encodeURIComponent(applicationId!)}/grants`),
  })
}

export function useApplicationGroups(offset: number, enabled = true) {
  return useQuery({
    queryKey: [...APPLICATION_GROUPS_KEY, offset],
    enabled,
    queryFn: () => apiFetch<ApplicationGroupListResponse>(`/admin/application-groups?limit=50&offset=${offset}`),
  })
}

export function useApplicationGroup(groupId: string | null) {
  return useQuery({
    queryKey: [...APPLICATION_GROUPS_KEY, groupId],
    enabled: !!groupId,
    queryFn: () => apiFetch<ApplicationGroup>(`/admin/application-groups/${encodeURIComponent(groupId!)}`),
  })
}

export function useApplicationSettings() {
  return useQuery({
    queryKey: APPLICATION_SETTINGS_KEY,
    queryFn: () => apiFetch<ApplicationSettings>('/admin/application-settings'),
  })
}

export function useApplicationSessions(offset: number) {
  return useQuery({
    queryKey: [...APPLICATION_SESSIONS_KEY, offset],
    queryFn: () => apiFetch<ApplicationSessionsResponse>(`/auth/application-sessions?limit=50&offset=${offset}`),
  })
}

export function useApplicationMutations() {
  const client = useQueryClient()
  const refresh = () => {
    void client.invalidateQueries({ queryKey: ADMIN_APPLICATIONS_KEY })
    void client.invalidateQueries({ queryKey: APPLICATIONS_KEY })
    void client.invalidateQueries({ queryKey: APPLICATION_SESSIONS_KEY })
  }

  const create = useMutation({
    mutationFn: (value: ApplicationConfigInput) => apiFetch('/admin/applications', { method: 'POST', body: JSON.stringify(value) }),
    onSuccess: refresh,
  })
  const update = useMutation({
    mutationFn: ({ id, value, expectedVersion }: { id: string; value: ApplicationConfigInput; expectedVersion: number }) =>
      apiFetch(`/admin/applications/${encodeURIComponent(id)}`, {
        method: 'PUT', body: JSON.stringify({ ...value, expected_version: expectedVersion }),
      }),
    onSuccess: refresh,
    onError: () => { void client.invalidateQueries({ queryKey: ADMIN_APPLICATIONS_KEY }) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/admin/applications/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: refresh,
  })
  const grants = useMutation({
    mutationFn: ({ id, grants, expectedVersion }: { id: string; grants: ApplicationGrantsResponse['grants']; expectedVersion: number }) =>
      apiFetch(`/admin/applications/${encodeURIComponent(id)}/grants`, {
        method: 'PUT', body: JSON.stringify({ grants, expected_version: expectedVersion }),
      }),
    onSuccess: (_data, vars) => {
      void client.invalidateQueries({ queryKey: [...ADMIN_APPLICATIONS_KEY, vars.id, 'grants'] })
      refresh()
    },
    onError: (_error, vars) => { void client.invalidateQueries({ queryKey: [...ADMIN_APPLICATIONS_KEY, vars.id, 'grants'] }) },
  })
  const createGroup = useMutation({
    mutationFn: (name: string) => apiFetch('/admin/application-groups', { method: 'POST', body: JSON.stringify({ name }) }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: APPLICATION_GROUPS_KEY }) },
  })
  const updateGroup = useMutation({
    mutationFn: ({ id, name, userIds, expectedVersion }: { id: string; name: string; userIds: string[]; expectedVersion: number }) =>
      apiFetch(`/admin/application-groups/${encodeURIComponent(id)}`, {
        method: 'PUT', body: JSON.stringify({ name, user_ids: userIds, expected_version: expectedVersion }),
      }),
    onSuccess: (_data, vars) => {
      void client.invalidateQueries({ queryKey: APPLICATION_GROUPS_KEY })
      void client.invalidateQueries({ queryKey: [...APPLICATION_GROUPS_KEY, vars.id] })
      void client.invalidateQueries({ queryKey: ADMIN_APPLICATIONS_KEY })
    },
    onError: (_error, vars) => { void client.invalidateQueries({ queryKey: [...APPLICATION_GROUPS_KEY, vars.id] }) },
  })
  const deleteGroup = useMutation({
    mutationFn: (id: string) => apiFetch(`/admin/application-groups/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: APPLICATION_GROUPS_KEY }) },
  })
  const saveSettings = useMutation({
    mutationFn: (value: ApplicationSettings) => apiFetch('/admin/application-settings', {
      method: 'PUT', body: JSON.stringify({ idle_seconds: value.idle_seconds, max_seconds: value.max_seconds, expected_version: value.version }),
    }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: APPLICATION_SETTINGS_KEY }) },
  })
  const revokeSession = useMutation({
    mutationFn: (id: string) => apiFetch(`/auth/application-sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: APPLICATION_SESSIONS_KEY }) },
  })
  return { create, update, remove, grants, createGroup, updateGroup, deleteGroup, saveSettings, revokeSession }
}

export function useApplicationUserSubjects(offset: number, search: string, enabled = true) {
  const query = new URLSearchParams({ limit: '50', offset: String(offset) })
  if (search.trim()) query.set('q', search.trim())
  return useQuery({
    queryKey: ['application-user-subjects', offset, search],
    enabled,
    queryFn: () => apiFetch<ApplicationUserSubjectsResponse>(`/admin/application-subjects/users?${query.toString()}`),
  })
}

export function useApplicationDirectoryGroups(search: string, enabled = true) {
  const query = new URLSearchParams()
  if (search.trim()) query.set('q', search.trim())
  return useQuery({
    queryKey: ['application-directory-groups', search],
    enabled,
    queryFn: () => apiFetch<ApplicationDirectoryGroupsResponse>(`/admin/application-subjects/directory-groups?${query.toString()}`),
  })
}
