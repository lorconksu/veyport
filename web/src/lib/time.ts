/**
 * Formats a UTC timestamp string as a human-readable relative time (e.g. "5 min ago").
 * Returns '—' when the input is null or empty.
 */
export function relativeTime(dateStr: string | null): string {
  if (!dateStr) return '—'
  // Server sends UTC timestamps without 'Z' suffix — ensure correct parsing
  const normalized = dateStr.endsWith('Z') ? dateStr : dateStr.replace(' ', 'T') + 'Z'
  const date = new Date(normalized)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return `${diffSec}s ago`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin} min ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDay = Math.floor(diffHr / 24)
  return `${diffDay}d ago`
}

/** Sentinel value stored in `locked_until` meaning "no auto-unlock". */
export const NO_AUTO_UNLOCK_ISO_PREFIX = '9999-12-31'

/** True when `iso` is the far-future "no auto-unlock" sentinel. */
export function isNoAutoUnlock(iso: string | null | undefined): boolean {
  return !!iso && iso.startsWith(NO_AUTO_UNLOCK_ISO_PREFIX)
}

/** True when `iso` names a moment strictly after `now` (defaults to the current time). */
export function isFuture(iso: string, now: Date = new Date()): boolean {
  return new Date(iso).getTime() > now.getTime()
}

function pad2(n: number): string {
  return String(n).padStart(2, '0')
}

/**
 * Formats an ISO timestamp relative to `now` (defaults to the current time):
 * "just now" (<60s), "N minute(s) ago" (<1h), "N hour(s) ago" (<24h),
 * "N day(s) ago" (<30 days), otherwise "on YYYY-MM-DD".
 */
export function formatRelative(iso: string, now: Date = new Date()): string {
  const date = new Date(iso)
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)

  if (diffSec < 60) return 'just now'

  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return diffMin === 1 ? '1 minute ago' : `${diffMin} minutes ago`

  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return diffHr === 1 ? '1 hour ago' : `${diffHr} hours ago`

  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 30) return diffDay === 1 ? '1 day ago' : `${diffDay} days ago`

  return `on ${date.getUTCFullYear()}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())}`
}
