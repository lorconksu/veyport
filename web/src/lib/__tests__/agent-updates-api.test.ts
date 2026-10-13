import { vi } from 'vitest'
import { apiFetch, apiFetchOnce } from '../api'
import { agentUpdateStatus, canStartAgentUpdate, checkAgentUpdate, startAgentUpdate } from '../agent-updates-api'
import type { AgentUpdate, AgentUpdateCheck } from '@/types/agent-updates'

vi.mock('../api', () => ({ apiFetch: vi.fn(), apiFetchOnce: vi.fn() }))

const target = { os: 'linux', arch: 'amd64', version: 'v2.0.0', revision: 'new', sha256: 'a'.repeat(64), bytes: 100 }
const check: AgentUpdateCheck = { supported: true, update_available: true, bootstrap_required: false,
  bootstrap_idle_confirmation_required: false, connection_id: 'connection', target,
  current: { version: 'v1.0.0', revision: 'old', sha256: 'b'.repeat(64) } }
const op: AgentUpdate = { id: 'op1', node_id: 'node/1', state: 'requested', target, expires_at: 200, created_at: 100, updated_at: 100 }

beforeEach(() => vi.clearAllMocks())

it('starts once with only the exact checked version and revision', async () => {
  vi.mocked(apiFetchOnce).mockResolvedValue({ operation: op })
  expect(await startAgentUpdate('node/1', check)).toEqual(op)
  expect(apiFetchOnce).toHaveBeenCalledExactlyOnceWith('/servers/node%2F1/agent-update', expect.objectContaining({
    method: 'POST', body: JSON.stringify({ expected_version: target.version, expected_revision: target.revision }),
  }))
  expect(apiFetch).not.toHaveBeenCalled()
})

it.each([
  { ...check, bootstrap_required: true }, { ...check, bootstrap_idle_confirmation_required: true },
  { ...check, supported: false }, { ...check, update_available: false },
  { ...check, operation: { ...op, state: 'unknown' as const } },
])('refuses unsupported, legacy, current or unresolved agents before POST', async checked => {
  expect(canStartAgentUpdate(checked)).toBe(false)
  await expect(startAgentUpdate('node/1', checked)).rejects.toThrow('cannot be updated')
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it.each([
  { ...op, id: '' }, { ...op, node_id: 'other' }, { ...op, target: { ...target, revision: 'changed' } },
])('rejects start responses with invalid identity or target', async value => {
  vi.mocked(apiFetchOnce).mockResolvedValue({ operation: value })
  await expect(startAgentUpdate('node/1', check)).rejects.toThrow('invalid update operation')
})

it('validates node and operation identity in status', async () => {
  vi.mocked(apiFetch).mockResolvedValue({ ...op, id: 'wrong' })
  await expect(agentUpdateStatus('node/1', 'op1')).rejects.toThrow('invalid update operation')
  expect(apiFetch).toHaveBeenCalledWith('/servers/node%2F1/agent-update/status?operation_id=op1', expect.anything())
})

it.each(['observed_version', 'observed_revision', 'observed_sha256'])('refuses success without exact %s evidence', async field => {
  vi.mocked(apiFetch).mockResolvedValue({ ...op, state: 'succeeded', observed_version: target.version,
    observed_revision: target.revision, observed_sha256: target.sha256, [field]: 'wrong' })
  await expect(agentUpdateStatus('node/1', 'op1')).rejects.toThrow('success is unverified')
})

it('accepts only verified success and validates availability operation identity', async () => {
  const success = { ...op, state: 'succeeded', observed_version: target.version,
    observed_revision: target.revision, observed_sha256: target.sha256 }
  vi.mocked(apiFetch).mockResolvedValue(success)
  expect(await agentUpdateStatus('node/1', 'op1', undefined, target)).toEqual(success)
  vi.mocked(apiFetch).mockResolvedValue({ ...check, operation: { ...op, node_id: 'other' } })
  await expect(checkAgentUpdate('node/1')).rejects.toThrow('invalid update operation')
})

it('rejects malformed checks and unexpected bootstrap tickets', async () => {
  vi.mocked(apiFetch).mockResolvedValue({ ...check, target: { ...target, sha256: 'bad' } })
  await expect(checkAgentUpdate('node/1')).rejects.toThrow('invalid update check')
  vi.mocked(apiFetchOnce).mockResolvedValue({ operation: op, bootstrap_ticket: 'ticket' })
  await expect(startAgentUpdate('node/1', check)).rejects.toThrow('Unexpected bootstrap')
})

it.each(['expired', 'failed'] as const)('inspects a %s legacy bootstrap without an architecture or digest', async state => {
  const legacy = { ...op, state, target: { ...target, arch: '', sha256: '', bytes: 0 } }
  vi.mocked(apiFetch).mockResolvedValue(legacy)
  expect(await agentUpdateStatus('node/1', 'op1')).toEqual(legacy)
})
