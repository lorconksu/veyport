import { apiFetchOnce } from '@/lib/api'

export function safeApplicationPath(value: string | null | undefined): string {
  const path = value || '/'
  if (path.length > 4096 || !path.startsWith('/') || path.startsWith('//') || /[\\\r\n\0]/.test(path)) throw new Error('Invalid application destination')
  const pathname = path.split('?')[0]
  let decoded: string
  try { decoded = decodeURIComponent(pathname) } catch { throw new Error('Invalid application destination') }
  if (decoded.startsWith('//') || decoded.startsWith('/_veyport/') || /[\\\r\n\0]/.test(decoded) || decoded.split('/').some(part => part === '.' || part === '..')) throw new Error('Invalid application destination')
  return path
}

export function safeApplicationReturn(value: unknown): string {
  if (typeof value !== 'string' || value.length > 8192 || !/^\/applications\/[a-zA-Z0-9-]+\/launch(?:\?|$)/.test(value)) return '/'
  try {
    const url = new URL(value, 'https://portal.invalid')
    if (url.origin !== 'https://portal.invalid' || url.hash || /[\\\r\n\0]/.test(value)) return '/'
    safeApplicationPath(url.searchParams.get('path'))
    return url.pathname + url.search
  } catch { return '/' }
}

export async function launchApplication(id: string, path: string): Promise<void> {
  if (!/^[a-zA-Z0-9-]+$/.test(id)) throw new Error('Invalid application')
  const destination = safeApplicationPath(path)
  const response = await apiFetchOnce<{ launch_url: string; ticket: string; path: string; expires_at: string }>(`/applications/${id}/launch`, { method: 'POST', body: JSON.stringify({ path: destination }) })
  const action = new URL(response.launch_url)
  // Host binding is decided by the authenticated portal server. Restrict protocol,
  // endpoint and authority grammar again before sending only the single-use ticket.
  if (action.protocol !== 'https:' || action.username || action.password || action.port || action.pathname !== '/_veyport/launch' || action.search || action.hash || !/^[a-z0-9.-]+$/.test(action.hostname) || !/^[A-Za-z0-9_-]{43}$/.test(response.ticket) || safeApplicationPath(response.path) !== destination) throw new Error('Invalid application launch response')
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = action.href
  const input = document.createElement('input')
  input.type = 'hidden'
  input.name = 'ticket'
  input.value = response.ticket
  form.append(input)
  document.body.append(form)
  form.submit()
  form.remove()
}
