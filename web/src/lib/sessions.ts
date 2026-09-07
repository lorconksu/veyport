import type { Session } from '@/types/api'

/** SSH and web-terminal sessions are shells: ending one terminates a live shell. */
export function isShell(session: Session): boolean {
  return session.kind === 'ssh' || session.kind === 'terminal'
}
