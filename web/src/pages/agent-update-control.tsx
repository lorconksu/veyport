import { sameArtifact, terminalAgentUpdate } from '@/lib/agent-updates-api'
import type { Server } from '@/types/api'
import type { AgentUpdateAttempt } from '@/types/agent-updates'
import type { AgentUpdateAvailability } from '@/hooks/use-agent-updates'

export function AgentUpdateControl({ server, availability, attempt, onClick }: Readonly<{
  server: Server
  availability?: AgentUpdateAvailability
  attempt?: AgentUpdateAttempt
  onClick: () => void
}>) {
  if (server.status === 'pending') return <span className="block mt-1 text-xs text-text-faint">Waiting for agent</span>
  const check = availability?.check
  const retained = attempt?.operation
  const checked = check?.operation
  // Closing the modal stops its status poll, but page availability still
  // returns validated durable outcomes for the same operation and artifact.
  const op = retained && checked && checked.id === retained.id && sameArtifact(checked.target, retained.target)
    && terminalAgentUpdate(checked) ? checked : retained ?? checked
  let label = 'Checking update...'
  if (attempt?.uncertain || (op && !terminalAgentUpdate(op))) label = 'Inspect update'
  else if (server.status !== 'online') label = 'Inspect update'
  else if (availability?.error) label = 'Check update'
  else if (check?.bootstrap_required) label = 'Manual upgrade required'
  else if (check && !check.supported) label = 'Update unsupported'
  else if (check?.update_available) label = 'Update available'
  else if (check) label = 'Up to date'
  return <button type="button" onClick={onClick} aria-label={`${label} for ${server.name}`}
    title={availability?.error?.message ?? check?.reason}
    className="block text-xs text-accent hover:underline mt-1 text-left">{label}</button>
}
