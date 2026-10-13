export interface ExecutionIdentity {
  username: string
  uid: number
  gid: number
  groups: number[]
  groups_sha256: string
  identity_sha256: string
  home: string
  shell: string
  cwd: string
}

export interface ExecutionPreparation {
  preparation_id: string
  boot_id: string
  expires_unix_milli: number
  limits: {
    max_frame_bytes: number
    max_buffer_bytes: number
    runtime_seconds: number
    term_grace_seconds: number
    blocked_consumer_seconds: number
  }
  identity: ExecutionIdentity
}

export interface ExecutionView {
  id: string
  enhanced: boolean
  actor_id: string
  actor_name: string
  actor_provider: string
  actor_person_id: string
  actor_subject: string
  node_id: string
  node_name: string
  requested_user: string
  command_sha256: string
  command_length: number
  script_sha256?: string
  script_length: number
  policy_version: string
  policy_sha256: string
  state: string
  evidence_state: string
  exit_code?: number
  signal?: string
  preparation: ExecutionPreparation | null
  originals: OriginalKind[]
  admission_event_id?: string
  admission_record_sha256?: string
  admission_disposition?: string
  created_at: string
  updated_at: string
  finished_at?: string
}

export interface ExecutionFilters {
  actor_id?: string
  node_id?: string
  os_user?: string
  policy_version?: string
  state?: string
  evidence_state?: string
}

export interface ExecutionsPage {
  executions: ExecutionView[]
  total: number
  limit: number
  offset: number
}

export type OriginalKind = 'envelope' | 'script'

export interface OriginalRequest {
  purpose: string
  records: [OriginalKind]
}

export interface OriginalDescriptor {
  kind: OriginalKind
  event_id: string
  sha256: string
  bytes: number
  version_id: string
}

export interface OriginalPreview {
  action: 'audit.original.read'
  digest: string
  records: OriginalDescriptor[]
}

export interface OriginalHandle {
  handle: string
  expires_at: string
  download_url: string
}
