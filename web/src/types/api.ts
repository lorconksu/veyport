export type Role = 'admin' | 'auditor' | 'viewer'

export interface User {
  id: string
  username: string
  email: string
  role: Role
  auth_provider?: 'local' | 'ldap'
  terminal_access?: boolean
  totp_enabled: boolean
  avatar: string | null
  must_change_password?: boolean
  temp_password_expires_at?: string | null
  created_at: string
  updated_at: string
}

export interface AuthStatusResponse {
  initialized: boolean
  version: string
}

export interface HealthResponse {
  status: string
  audit: AuditHealth
}

export interface RegisterRequest {
  username: string
  email: string
  password: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  totp_token?: string
  setup_token?: string
  requires_totp_setup?: boolean
  must_change_password?: boolean
}

export interface LoginTOTPRequest {
  totp_token: string
  code: string
}

export interface AuthResponse {
  access_token?: string
  refresh_token?: string
  user: User
}

export interface TokenPair {
  access_token?: string
  refresh_token?: string
}

export interface TOTPSetupResponse {
  secret: string
  qr_url: string
}

export interface TOTPEnableRequest {
  code: string
  new_password?: string
}

export interface CreateUserRequest {
  username: string
  email: string
  role: Role
}

export interface CreateUserResponse {
  user: User
  temporary_password: string
}

export interface AuditEntry {
  id: string
  user_id: string | null
  action: string
  target: string | null
  detail: string | null
  ip_address: string | null
  outcome: string
  actor_type: string
  correlation_id: string | null
  resource_type: string | null
  created_at: string
}

export interface AuditLogResponse {
  entries: AuditEntry[]
  total: number
  limit: number
  offset: number
}

export interface AuditHealth {
  failure_count: number
  last_failure_at: string | null
  last_failure_reason: string | null
  degraded: boolean
  last_recovered_at: string | null
}

export interface AuditThresholds {
  login_failures_per_hour: number
  registration_failures_per_hour: number
  privileged_actions_per_hour: number
}

export interface AuditSettings {
  retention_days: number
  review_reminder_days: number
  password_history_count: number
  temporary_password_ttl_hours: number
  thresholds: AuditThresholds
}

export interface AuditCatalogEntry {
  action: string
  label: string
  category: string
  outcome: string
  actor_type: string
  resource_type: string
}

export interface AuditCatalogResponse {
  entries: AuditCatalogEntry[]
  last_updated_at: string
}

export interface AuditSavedFilter {
  id: string
  name: string
  created_by: string
  filters_json: string
  created_at: string
  updated_at: string
}

export interface AuditSavedFiltersResponse {
  filters: AuditSavedFilter[]
}

export interface AuditReview {
  id: string
  reviewer_id: string
  reviewer: string
  filters_json: string
  notes: string
  from: string | null
  to: string | null
  completed_at: string
  created_at: string
}

export interface AuditReviewsResponse {
  reviews: AuditReview[]
}

export interface AuditDetection {
  id: string
  type: string
  severity: string
  title: string
  description: string
}

export interface AuditDetectionsResponse {
  detections: AuditDetection[]
}

export interface AuditManifest {
  generated_at: string
  generated_by: string
  record_count: number
  applied_filters: string
  first_created_at?: string
  last_created_at?: string
}

export interface AuditExportResponse {
  manifest: AuditManifest
  entries: AuditEntry[]
}

export interface AuditExportHistoryResponse {
  entries: AuditEntry[]
}

export interface AuditFlag {
  id: string
  entry_id: string | null
  created_by: string
  created_by_id: string
  filters_json: string
  note: string
  created_at: string
}

export interface AuditFlagsResponse {
  flags: AuditFlag[]
}

export interface AuditRetentionRunResponse {
  deleted_count: number
  cutoff: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface UpdateRoleRequest {
  role: Role
}

export interface TOTPDisableRequest {
  user_id: string
  admin_totp_code: string
}

export interface ApiError {
  error: string
}

export type ServerStatus = 'pending' | 'online' | 'offline'

export interface Server {
  id: string
  name: string
  hostname: string | null
  ip_address: string | null
  os: string | null
  status: ServerStatus
  agent_version: string | null
  labels: string
  last_seen_at: string | null
  created_at: string
  updated_at: string
}

export interface ServerListResponse {
  servers: Server[]
  total: number
  limit: number
  offset: number
}

export interface CreateServerRequest {
  name: string
  labels?: string
}

export interface CreateServerResponse {
  server: Server
  registration_token: string
  install_command: string
}

export interface BatchDeleteRequest {
  ids: string[]
}

// File tree types (sub-project 4)
export interface FileNode {
  name: string
  path: string
  is_dir: boolean
  size: number
  readable: boolean
}

export interface FileListResponse {
  files: FileNode[]
}

export interface FileReadResponse {
  data: string  // base64-encoded
  total_size: number
  mime_type: string
}

export interface TerminalSessionResponse {
  session_id: string
}

export interface PathPermission {
  id: string
  user_id: string
  username: string
  server_id: string
  path: string
  created_at: string
}

export interface PathListResponse {
  paths: PathPermission[]
}

export interface CreatePathRequest {
  user_id: string
  path: string
}

export interface SMTPConfig {
  host: string
  port: number
  username: string
  password: string
  from: string
  tls: boolean
  enabled: boolean
}

export interface NotificationPreference {
  event_type: string
  label: string
  category: string
  enabled: boolean
}

export interface NotificationLogEntry {
  id: string
  user_id: string
  username: string
  event_type: string
  subject: string
  status: 'sent' | 'failed'
  error: string | null
  created_at: string
}
