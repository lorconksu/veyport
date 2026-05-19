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
