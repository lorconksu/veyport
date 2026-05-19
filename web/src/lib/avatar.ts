const AVATAR_COLORS = [
  '#3b82f6', // blue
  '#8b5cf6', // violet
  '#06b6d4', // cyan
  '#10b981', // emerald
  '#f59e0b', // amber
  '#ef4444', // red
  '#ec4899', // pink
  '#6366f1', // indigo
]

const AVATAR_COLOR_KEY = 'veyport_avatar_color'

export function getAvatarColor(username: string): string {
  const stored = localStorage.getItem(AVATAR_COLOR_KEY)
  if (stored && AVATAR_COLORS.includes(stored)) return stored

  // Deterministic default based on username
  let hash = 0
  for (const ch of username) hash = Math.trunc(((hash << 5) - hash + (ch.codePointAt(0) ?? 0)))
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length]
}

export function setAvatarColor(color: string): void {
  localStorage.setItem(AVATAR_COLOR_KEY, color)
}

export { AVATAR_COLORS }
