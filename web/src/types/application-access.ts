export type ApplicationRoute = 'hub' | 'node'
export type ApplicationGrantKind = 'user' | 'role' | 'local_group' | 'directory_group'

export interface AuthorizedApplication {
  id: string
  name: string
  description: string
  public_url: string
  available: boolean
  availability_reason?: string
}

export interface ApplicationConfig {
  id: string
  name: string
  slug: string
  description: string
  public_hostname: string
  route: ApplicationRoute
  node_id?: string | null
  backend_url: string
  allowed_cidrs: string[]
  ca_pem?: string
  enabled: boolean
  config_version: number
  created_at: string
  updated_at: string
}

export interface ApplicationListResponse { applications: AuthorizedApplication[]; total: number }
export interface ApplicationAdminListResponse { applications: ApplicationConfig[]; total: number; limit?: number; offset?: number }
export interface ApplicationGrantsResponse { grants: Array<{ kind: ApplicationGrantKind; subject_id: string }>; config_version: number }
export interface ApplicationGroup { id: string; name: string; user_ids: string[]; member_count?: number; version: number }
export interface ApplicationGroupListResponse { groups: ApplicationGroup[]; total: number; limit?: number; offset?: number }
export interface ApplicationSettings { idle_seconds: number; max_seconds: number; version: number }
export interface ApplicationSession {
  id: string
  application_id: string
  application_name?: string
  user_id?: string
  created_at: string
  last_seen_at: string
  idle_deadline_at?: string
  expires_at: string
  ended_at?: string | null
  end_reason?: string
}
export interface ApplicationSessionsResponse { sessions: ApplicationSession[]; total: number }

export interface ApplicationConfigInput {
  name: string
  slug: string
  description: string
  route: ApplicationRoute
  node_id?: string
  backend_url: string
  allowed_cidrs: string[]
  ca_pem?: string
  enabled: boolean
}

export interface ApplicationUserSubject { id: string; username: string }
export interface ApplicationUserSubjectsResponse { users: ApplicationUserSubject[]; total: number }

export interface ApplicationDirectoryGroup { subject_id: string; name: string }
export interface ApplicationDirectoryGroupsResponse { groups: ApplicationDirectoryGroup[]; total: number }
