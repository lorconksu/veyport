import type { AssignedRole, AuditSettings, Capability, SecurityRole } from './api'

export interface AuditPolicy {
  profile: 'standard' | 'enhanced'
  actors: string[]
  nodes: string[]
  runtime_seconds: number
  retention_hours: number
  destination: string
  credential_ref: string
  trust_key_ids: string[]
  qualification_sha256: string
}

export interface AuditPolicyVersion {
  version: number
  policy: AuditPolicy
  sha256: string
  request_id?: string
}

export type AuditPolicyState = 'standard' | 'setup_pending' | 'enhanced' | 'applying' | 'recovery_required'

export interface SecurityReadiness {
  governance: boolean
  archive_and_transport: boolean
  enrollment_marker: boolean
}

interface PolicyStatusBase {
  state: AuditPolicyState
  capabilities: Capability[]
  governance_enrolled: boolean
}

export type AuditPolicyResponse = PolicyStatusBase & ({
  policy: AuditPolicyVersion
  pending: AuditPolicyVersion | null
  credential_set: boolean
  readiness: SecurityReadiness
} | {
  version: number
  profile: AuditPolicy['profile']
})

export interface SecurityNomination {
  user_id: string
  person_id: string
  roles: SecurityRole[]
  verification: string
}

export interface SecurityRoleChange {
  user_id: string
  role: SecurityRole
  grant: boolean
}

export interface SecurityPersonChange {
  user_id: string
  person_id: string
  verification: string
}

export interface SecurityRecovery {
  user_id: string
  operation: 'reenable' | 'mfa-reset' | 'password-reset'
  secret_ref?: string
}

// LDAP governance uses immutable bind references; the operational LDAP shape
// includes a write-only password and must never be reused for this payload.
export interface SecurityLDAPSettings {
  enabled: boolean
  url: string
  bind_dn: string
  bind_credential_ref: string
  clear_bind_password: boolean
  user_base_dn: string
  group_base_dn: string
  user_search_filter: string
  group_search_filter: string
  username_attribute: string
  email_attribute: string
  external_id_attribute: string
  group_name_attribute: string
  start_tls: boolean
  tls_server_name: string
  ca_cert_pem: string
  admin_groups: string[]
  auditor_groups: string[]
  viewer_groups: string[]
  terminal_groups: string[]
}

export type SecurityChangePayload =
  | { kind: 'bootstrap'; policy: AuditPolicy; nominations: SecurityNomination[] }
  | { kind: 'policy'; policy: AuditPolicy }
  | { kind: 'role'; role: SecurityRoleChange }
  | { kind: 'person'; person: SecurityPersonChange }
  | { kind: 'recovery'; recovery: SecurityRecovery }
  | { kind: 'audit-settings'; audit_settings: AuditSettings }
  | { kind: 'ldap'; ldap: SecurityLDAPSettings }

export interface SecurityProposal {
  reason: string
  expected_version: number
  change: SecurityChangePayload
}

export interface SecurityPreview {
  digest: string
  proposal: SecurityProposal
}

export interface SecurityApproval {
  user_id: string
  person_id: string
  proof_sha256: string
  approved_at: string
  invalidated_at?: string
}

export type SecurityChangeState = 'requested' | 'partially_approved' | 'approved' | 'applying'
  | 'applied' | 'expired' | 'superseded' | 'failed' | 'rejected'

export interface SecurityChange extends SecurityProposal {
  id: string
  revision: number
  requester_id: string
  requester_person_id: string
  applier_id?: string
  applier_person_id?: string
  digest: string
  state: SecurityChangeState
  created_at: string
  expires_at: string
  approvals: SecurityApproval[] | null
  intent_ref?: string
  commit_ref?: string
  result_ref?: string
}

export interface SecurityChangesPage {
  changes: SecurityChange[]
  limit: number
  offset: number
}

export type SecurityAction = 'security.request' | 'security.approve' | 'security.apply'

export interface SecurityStepupResponse {
  proof: string
  expires_at: string
}

export interface SecurityCredentialReference {
  credential_ref: string
  credential_set: boolean
}

export interface SecurityPrincipal {
  id: string
  username: string
  person_id: string
  roles: AssignedRole[]
  totp_enabled: boolean
}

export interface SecurityPrincipalsPage {
  principals: SecurityPrincipal[]
  total: number
  limit: number
  offset: number
}
