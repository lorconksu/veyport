import { hasCapability } from './auth'
import type { User } from '@/types/api'
import type { SecurityChange } from '@/types/security'

export function securityIdentityKey(user: User | null): string {
  return user ? JSON.stringify([user.id, user.username, user.auth_provider, user.person_id, user.totp_enabled, user.capabilities ?? [], user.roles ?? [], user.status]) : 'signed-out'
}

// Bootstrap nominations permit review of this single exact request. They never
// grant access to the broad policy, principal selector or request list.
export function canDecideChange(user: User | null, change: SecurityChange, action: 'approve' | 'apply' | 'reconcile'): boolean {
  if (!user?.totp_enabled || user.status === 'disabled' || user.status === 'locked') return false
  if (action !== 'reconcile' && (!Number.isFinite(Date.parse(change.expires_at)) || Date.parse(change.expires_at) <= Date.now())) return false
  const nomination = change.change.kind === 'bootstrap' ? change.change.nominations.find(item => item.user_id === user.id) : undefined
  if (action === 'approve') {
    if (!['requested', 'partially_approved'].includes(change.state) || user.id === change.requester_id) return false
    const person = nomination?.person_id ?? user.person_id
    if (!person || person === change.requester_person_id || change.approvals?.some(item => item.person_id === person)) return false
    return nomination ? nomination.roles.includes('security-approver') : hasCapability(user, 'security.approve')
  }
  if (change.state !== (action === 'reconcile' ? 'applying' : 'approved')) return false
  return nomination ? nomination.roles.includes('security-officer') && user.id === change.requester_id && hasCapability(user, 'security.bootstrap') : hasCapability(user, 'security.apply')
}
