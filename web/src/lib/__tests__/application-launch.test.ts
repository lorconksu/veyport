import { beforeEach, describe, expect, it, vi } from 'vitest'
import { launchApplication, safeApplicationPath, safeApplicationReturn } from '../application-launch'
import { apiFetchOnce } from '../api'
vi.mock('../api', () => ({ apiFetchOnce: vi.fn() }))

beforeEach(() => { vi.clearAllMocks(); document.body.innerHTML = '' })
describe('application destinations', () => {
  it('keeps native query data while restricting navigation to app-relative paths', () => {
    expect(safeApplicationPath('/native?next=https%3A%2F%2Fidp.example')).toBe('/native?next=https%3A%2F%2Fidp.example')
    expect(safeApplicationPath(undefined)).toBe('/')
    for (const path of ['//evil', 'https://evil', '/%5cevil', '/a/../b', '/%2e%2e/secret', '/_veyport/launch', '/%00', '/%invalid']) expect(() => safeApplicationPath(path)).toThrow()
  })
  it('allows only narrow launch routes after login', () => {
    const path = '/applications/abc-123/launch?path=%2Fnative%3Fx%3D1'
    expect(safeApplicationReturn(path)).toBe(path)
    for (const value of [null, {}, '//evil', 'https://evil', '/api/auth/logout', '/applications/abc/launch/extra', '/applications/abc/launch#evil', '/applications/abc/launch?path=%2F%2Fevil', '/applications/abc/launch?path=%2Fa%2F..%2Fb']) expect(safeApplicationReturn(value)).toBe('/')
  })
})
describe('one-use app launch', () => {
  it('POSTs only the app ticket to the server-selected exact HTTPS endpoint', async () => {
    vi.mocked(apiFetchOnce).mockResolvedValue({ launch_url: 'https://demo.apps.example.test/_veyport/launch', ticket: 'A'.repeat(43), path: '/native?x=1' })
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function (this: HTMLFormElement) {
      expect(this.method).toBe('post')
      expect(this.action).toBe('https://demo.apps.example.test/_veyport/launch')
      expect([...this.querySelectorAll('input')].map(input => [input.name, input.value])).toEqual([['ticket', 'A'.repeat(43)]])
    })
    await launchApplication('abc-123', '/native?x=1')
    expect(apiFetchOnce).toHaveBeenCalledWith('/applications/abc-123/launch', { method: 'POST', body: '{"path":"/native?x=1"}' })
    expect(submit).toHaveBeenCalledOnce()
    expect(document.querySelector('form')).toBeNull()
    submit.mockRestore()
  })
  it('refuses malformed responses before creating a form or spending another ticket', async () => {
    for (const response of [
      { launch_url: 'http://demo.apps.example.test/_veyport/launch', ticket: 'A'.repeat(43), path: '/' },
      { launch_url: 'https://demo.apps.example.test/_veyport/launch?ticket=secret', ticket: 'A'.repeat(43), path: '/' },
      { launch_url: 'https://user:pass@demo.apps.example.test/_veyport/launch', ticket: 'A'.repeat(43), path: '/' },
      { launch_url: 'https://demo.apps.example.test/_veyport/launch', ticket: 'invalid', path: '/' },
      { launch_url: 'https://demo.apps.example.test/_veyport/launch', ticket: 'A'.repeat(43), path: '/different' },
    ]) { vi.mocked(apiFetchOnce).mockResolvedValue(response); await expect(launchApplication('abc', '/')).rejects.toThrow(); expect(document.querySelector('form')).toBeNull() }
    await expect(launchApplication('../bad', '/')).rejects.toThrow()
  })
})
