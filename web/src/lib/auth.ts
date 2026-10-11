import type { AssignedRole, Capability, User } from '@/types/api'
import type { AuditPolicyResponse } from '@/types/security'

// CSRF token is stored in a non-httpOnly cookie readable by JS
export function getCSRFToken(): string {
  const match = /(?:^|;\s*)veyport_csrf=([^;]+)/.exec(document.cookie)
  return match ? match[1] : ''
}

// Access and refresh tokens are now in httpOnly cookies — not accessible from JS.
// clearTokens calls the server logout endpoint to clear cookies
export async function clearTokens(): Promise<void> {
  try {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
  } catch {
    // Best-effort — if server is unreachable, cookies will expire naturally
  }
}
export function assignedRoles(user: User | null | undefined): AssignedRole[] {
  if (!user) return []
  if ('roles' in user) return Array.isArray(user.roles) ? user.roles : []
  return [user.role]
}

// Server capabilities, including an explicit empty array, are authoritative.
// Older Standard responses retain their existing operational UI, but can never
// acquire governance/original-read authority through an admin/role fallback.
export function hasCapability(user: User | null | undefined, capability: Capability): boolean {
  if (!user) return false
  if ('capabilities' in user) return Array.isArray(user.capabilities) && user.capabilities.includes(capability)
  switch (capability) {
    case 'nodes.read': return true
    case 'operations.admin': return user.role === 'admin'
    case 'audit.read': return user.role === 'admin' || user.role === 'auditor'
    case 'terminal.execute': return user.role === 'admin' || user.terminal_access === true
    default: return false
  }
}

export function canBootstrapSecurity(user: User | null | undefined, policy: AuditPolicyResponse | undefined): boolean {
  const profile = policy && ('policy' in policy ? policy.policy.policy.profile : policy.profile)
  return hasCapability(user, 'security.bootstrap') && policy?.governance_enrolled === false && profile === 'standard'
}

export function canViewSecurity(user: User | null | undefined, policy?: AuditPolicyResponse): boolean {
  return hasCapability(user, 'security.read') || canBootstrapSecurity(user, policy)
}
