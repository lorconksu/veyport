export interface AgentArtifact {
  os: string
  arch: string
  version: string
  revision: string
  sha256: string
  bytes: number
}

export type AgentUpdateState = 'requested' | 'downloading' | 'installing' | 'bootstrap_required'
  | 'confirmation_pending' | 'rollback_confirmation_pending' | 'unknown'
  | 'succeeded' | 'failed' | 'rolled_back' | 'expired' | 'recovery_acknowledged'

export interface AgentUpdate {
  id: string
  node_id: string
  state: AgentUpdateState
  reason?: string
  target: AgentArtifact
  previous_version?: string
  previous_revision?: string
  previous_sha256?: string
  observed_version?: string
  observed_revision?: string
  observed_sha256?: string
  expires_at: number
  created_at: number
  updated_at: number
}

export interface AgentUpdateCheck {
  supported: boolean
  reason?: string
  update_available: boolean
  bootstrap_required: boolean
  bootstrap_idle_confirmation_required: boolean
  connection_id: string
  current?: { version: string; revision: string; sha256: string } | null
  target: AgentArtifact
  operation?: AgentUpdate
}

// Kept only in this authenticated dashboard instance. Durable status lives in
// the Hub; opening a new dashboard retrieves the latest operation from it.
export interface AgentUpdateAttempt {
  operation?: AgentUpdate
  uncertain?: boolean
  previousOperationId?: string
  target?: AgentArtifact
}
