import { ApiError } from '../api'
import {
  listExecutions, getExecution, previewOriginalAccess, originalAccessStepUp,
  requestOriginalAccess, downloadOriginal,
} from '../executions-api'
import type { OriginalHandle, OriginalRequest } from '@/types/executions'

const mockFetch = vi.fn<typeof fetch>()
const digest = 'd'.repeat(64)
const handle = 'e'.repeat(64)
const access: OriginalHandle = { handle, expires_at: 'soon', download_url: `/api/audit-originals/${handle}` }
const request: OriginalRequest = { purpose: 'Investigate incident 123', records: ['script'] }
function response(body: unknown, status = 200): Response { return new Response(JSON.stringify(body), { status }) }

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch)
  mockFetch.mockReset()
  document.cookie = '__Host-veyport_csrf=session-csrf; Path=/; Secure'
})
afterEach(() => {
  vi.unstubAllGlobals()
  document.cookie = '__Host-veyport_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure'
})

it('returns execution metadata, preserving null preparation and real root identity', async () => {
  const denied = { id: 'denied', preparation: null, originals: [] }
  mockFetch.mockResolvedValueOnce(response({ executions: [denied], total: 1, limit: 10, offset: 2 }))
    .mockResolvedValueOnce(response({ id: 'root', preparation: { identity: { uid: 0, username: 'root' } } }))
  const page = await listExecutions({ actor_id: 'person one', state: 'denied' }, 10, 2)
  expect(page.executions[0].preparation).toBeNull()
  const detail = await getExecution('root')
  expect(detail.preparation?.identity.uid).toBe(0)
  expect(mockFetch.mock.calls[0][0]).toBe('/api/executions?limit=10&offset=2&actor_id=person+one&state=denied')
  expect(mockFetch.mock.calls.every(call => call[1]?.cache === 'no-store')).toBe(true)
})

it('binds a single original to exact purpose/digest, session MFA and independent handle request', async () => {
  mockFetch.mockResolvedValueOnce(response({ action: 'audit.original.read', digest, records: [{ kind: 'script', event_id: 'event', sha256: digest, bytes: 4, version_id: 'v1' }] }))
    .mockResolvedValueOnce(response({ proof: 'fresh-original-proof', expires_at: 'soon' }))
    .mockResolvedValueOnce(response(access, 201))
  const preview = await previewOriginalAccess('execution-1', request)
  const proof = await originalAccessStepUp('execution-1', request, preview.digest, '123456')
  await expect(requestOriginalAccess('execution-1', request, preview.digest, proof.proof)).resolves.toEqual(access)
  expect(mockFetch.mock.calls.map(call => call[0])).toEqual([
    '/api/executions/execution-1/original-access/preview', '/api/executions/execution-1/original-access/step-up', '/api/executions/execution-1/original-access',
  ])
  expect(JSON.parse(String(mockFetch.mock.calls[1][1]?.body))).toEqual({ ...request, digest, code: '123456' })
  expect(JSON.parse(String(mockFetch.mock.calls[2][1]?.body))).toEqual({ ...request, digest, step_up_proof: 'fresh-original-proof' })
  expect((mockFetch.mock.calls[2][1]?.headers as Headers).get('X-CSRF-Token')).toBe('session-csrf')
})

it.each([401, 403, 503])('does not replay original authority after HTTP %i', async status => {
  mockFetch.mockResolvedValueOnce(response({ error: 'original refused fresh-original-proof' }, status))
  await expect(requestOriginalAccess('e1', request, digest, 'fresh-original-proof')).rejects.toMatchObject({ status, message: 'original refused [redacted]' })
  expect(mockFetch).toHaveBeenCalledTimes(1)
})

it('fetches controlled bytes once with no redirects/cache and returns a safe filename', async () => {
  mockFetch.mockResolvedValueOnce(new Response('whole script', { headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="script.sh"' } }))
  const download = await downloadOriginal(access)
  expect(await download.blob.text()).toBe('whole script')
  expect(download.filename).toBe('script.sh')
  expect(mockFetch).toHaveBeenCalledWith(access.download_url, expect.objectContaining({ cache: 'no-store', redirect: 'error', credentials: 'same-origin' }))
  expect(mockFetch).toHaveBeenCalledTimes(1)
})

it.each([401, 403, 503])('rejects download HTTP %i before opening/saving bytes and never retries', async status => {
  mockFetch.mockResolvedValueOnce(response({ error: `download refused ${handle}` }, status))
  const error = await downloadOriginal(access).catch(error => error)
  expect(error).toBeInstanceOf(ApiError)
  expect(error).toMatchObject({ status, message: 'download refused [redacted]' })
  expect(mockFetch).toHaveBeenCalledTimes(1)
})

it('refuses redirected URL substitution and malformed bounded selection before HTTP', async () => {
  await expect(downloadOriginal({ ...access, download_url: 'https://unrelated.example' })).rejects.toThrow('Exact one-use')
  expect(() => previewOriginalAccess('../users', request)).toThrow('ID')
  expect(() => previewOriginalAccess('e', { purpose: ' secret\n', records: ['script'] })).toThrow('Purpose')
  expect(() => previewOriginalAccess('e', { purpose: 'x'.repeat(1025), records: ['script'] })).toThrow('Purpose')
  expect(() => previewOriginalAccess('e', { ...request, records: ['script', 'envelope'] as unknown as ['script'] })).toThrow('one selected')
  expect(() => originalAccessStepUp('e', request, digest, 'bad')).toThrow('MFA')
  expect(() => requestOriginalAccess('e', request, 'bad', 'proof')).toThrow('digest')
  expect(() => requestOriginalAccess('e', request, digest, '')).toThrow('proof')
  expect(() => listExecutions({ state: '\n' })).toThrow('filters')
  expect(() => listExecutions({}, 0)).toThrow('pagination')
  expect(mockFetch).not.toHaveBeenCalled()
})

it('treats aborted download as uncertain without another request and redacts the handle', async () => {
  mockFetch.mockRejectedValueOnce(new DOMException(`aborted ${handle}`, 'AbortError'))
  await expect(downloadOriginal(access)).rejects.toThrow('aborted [redacted]')
  expect(mockFetch).toHaveBeenCalledTimes(1)
})

it('refuses a nonbinary response and neutralizes an unsafe download filename', async () => {
  mockFetch.mockResolvedValueOnce(response({ raw: 'not a download' }))
  await expect(downloadOriginal(access)).rejects.toThrow('content type')
  mockFetch.mockResolvedValueOnce(new Response('bytes', { headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="../secret"' } }))
  expect((await downloadOriginal(access)).filename).toBe('audit-original.bin')
})
