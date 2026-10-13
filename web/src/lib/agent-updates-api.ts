import { apiFetch, apiFetchOnce } from './api'
import type { AgentArtifact, AgentUpdate, AgentUpdateCheck } from '@/types/agent-updates'

const states = new Set(['requested', 'downloading', 'installing', 'bootstrap_required', 'confirmation_pending',
  'rollback_confirmation_pending', 'unknown', 'succeeded', 'failed', 'rolled_back', 'expired', 'recovery_acknowledged'])

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object'
}
function identifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128
    && !value.includes(String.fromCharCode(0)) && !/[\r\n]/.test(value)
}
function hash(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
}
function artifact(value: unknown, bootstrap = false): value is AgentArtifact {
  return record(value) && identifier(value.version) && identifier(value.revision) && value.os === 'linux'
    && (bootstrap || ((value.arch === 'amd64' || value.arch === 'arm64') && hash(value.sha256)
      && typeof value.bytes === 'number' && Number.isSafeInteger(value.bytes) && value.bytes > 0))
}
export function sameArtifact(a: AgentArtifact, b: AgentArtifact): boolean {
  return a.version === b.version && a.revision === b.revision && a.sha256 === b.sha256
    && a.os === b.os && a.arch === b.arch && a.bytes === b.bytes
}

function operation(value: unknown, nodeId: string, operationId?: string, target?: AgentArtifact): AgentUpdate {
  const incompleteBootstrap = record(value) && record(value.target) && value.target.arch === ''
    && value.target.sha256 === '' && value.target.bytes === 0 && value.state !== 'succeeded'
  if (!record(value) || !identifier(value.id) || value.node_id !== nodeId || (operationId && value.id !== operationId)
    || typeof value.state !== 'string' || !states.has(value.state) || !artifact(value.target, incompleteBootstrap)
    || !['expires_at', 'created_at', 'updated_at'].every(key => typeof value[key] === 'number' && Number.isFinite(value[key]))
    || (target && !sameArtifact(value.target, target))) {
    throw new Error('Hub returned a different or invalid update operation. Inspect status before taking further action.')
  }
  if (value.state === 'succeeded' && (value.observed_version !== value.target.version
    || value.observed_revision !== value.target.revision || value.observed_sha256 !== value.target.sha256)) {
    throw new Error('Update success is unverified: the enrolled agent has not confirmed the exact target artifact.')
  }
  return value as unknown as AgentUpdate
}

function options(signal?: AbortSignal): RequestInit {
  const timeout = AbortSignal.timeout(15_000)
  return { cache: 'no-store', signal: signal ? AbortSignal.any([signal, timeout]) : timeout }
}
function base(nodeId: string): string {
  return `/servers/${encodeURIComponent(nodeId)}/agent-update`
}

export async function checkAgentUpdate(nodeId: string, signal?: AbortSignal): Promise<AgentUpdateCheck> {
  const value = await apiFetch<unknown>(base(nodeId), options(signal))
  if (!record(value) || !['supported', 'update_available', 'bootstrap_required', 'bootstrap_idle_confirmation_required'].every(key => typeof value[key] === 'boolean')
    || !artifact(value.target, value.bootstrap_required === true) || !identifier(value.connection_id)
    || (value.supported && (!record(value.current) || !identifier(value.current.version) || !identifier(value.current.revision) || !hash(value.current.sha256)))) {
    throw new Error('Hub returned an invalid update check. Refresh before taking further action.')
  }
  if (value.operation != null) operation(value.operation, nodeId)
  return value as unknown as AgentUpdateCheck
}

export async function agentUpdateStatus(nodeId: string, operationId?: string, signal?: AbortSignal, target?: AgentArtifact): Promise<AgentUpdate> {
  const query = operationId ? `?operation_id=${encodeURIComponent(operationId)}` : ''
  return operation(await apiFetch<unknown>(`${base(nodeId)}/status${query}`, options(signal)), nodeId, operationId, target)
}

export async function startAgentUpdate(nodeId: string, checked: AgentUpdateCheck): Promise<AgentUpdate> {
  if (!canStartAgentUpdate(checked)) throw new Error('This agent cannot be updated automatically.')
  const value = await apiFetchOnce<unknown>(base(nodeId), {
    ...options(), method: 'POST',
    body: JSON.stringify({ expected_version: checked.target.version, expected_revision: checked.target.revision }),
  })
  if (!record(value) || value.bootstrap_ticket) throw new Error('Unexpected bootstrap response. Inspect the update through the CLI.')
  return operation(value.operation, nodeId, undefined, checked.target)
}

export function terminalAgentUpdate(op: AgentUpdate): boolean {
  return ['succeeded', 'failed', 'rolled_back', 'expired', 'recovery_acknowledged'].includes(op.state)
}
export function canStartAgentUpdate(check: AgentUpdateCheck): boolean {
  return check.supported && check.update_available && !check.bootstrap_required && !check.bootstrap_idle_confirmation_required
    && !!check.current && (!check.operation || terminalAgentUpdate(check.operation))
}
