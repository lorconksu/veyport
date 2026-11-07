import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from '@/hooks/use-auth'
import { ServerDetailPage } from '../server-detail'

// The terminal is unrelated to file viewing. File decoding, highlighting,
// deferred search, the query cache and HTTP client all use their real code.
vi.mock('@/components/server-terminal', () => ({ ServerTerminal: () => null, OfflineTerminalState: () => null }))
const fetchMock = vi.fn<typeof fetch>()
let client: QueryClient
let router: ReturnType<typeof createMemoryRouter>
function json(value: unknown) { return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } }) }
async function openSearch() {
  router = createMemoryRouter([{ path: '/servers/:id', element: <ServerDetailPage /> }], { initialEntries: ['/servers/server-1'] })
  render(<QueryClientProvider client={client}><AuthProvider><RouterProvider router={router} /></AuthProvider></QueryClientProvider>)
  await userEvent.click(await screen.findByText('/etc'))
  await userEvent.click(await screen.findByText('example.txt'))
  await screen.findByTitle('Refresh file')
  await userEvent.click(screen.getByTitle('Search in file (Ctrl+F)'))
  return screen.getByPlaceholderText('Search in file...')
}
beforeEach(() => {
  sessionStorage.clear()
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } } })
  vi.stubGlobal('fetch', fetchMock.mockReset().mockImplementation(async input => {
    const url = String(input)
    if (url === '/api/auth/me') return json({ id: 'operator', username: 'operator', role: 'admin', capabilities: ['nodes.read'] })
    if (url === '/api/servers/server-1') return json({ id: 'server-1', name: 'Search server', status: 'online', hostname: 'host', labels: '' })
    if (url === '/api/servers/server-1/my-paths') return json({ paths: ['/etc'] })
    if (url === '/api/servers/server-1/files?path=%2Fetc') return json({ files: [{ name: 'example.txt', path: '/etc/example.txt', is_dir: false, readable: true, size: 22 }] })
    if (url === '/api/servers/server-1/files/read?path=%2Fetc%2Fexample.txt') return json({ data: btoa('hello one\nhello two\nend'), total_size: 23, mime_type: 'text/plain' })
    throw new Error(`Unexpected request: ${url}`)
  }))
})
afterEach(() => { cleanup(); client.clear(); router?.dispose(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('file search scrolling through the server detail page', () => {
  it('scrolls the actual active match on search and next/previous navigation, and stops when no match remains', async () => {
    const scrolled: Element[] = []
    // jsdom has no layout/scroll implementation. Record the receiver at the
    // browser DOM API boundary so an unrelated or stale element cannot pass.
    const scrollIntoView = vi.fn(function (this: Element) { scrolled.push(this) })
    const previous = Object.getOwnPropertyDescriptor(Element.prototype, 'scrollIntoView')
    Object.defineProperty(Element.prototype, 'scrollIntoView', { configurable: true, value: scrollIntoView })
    try {
      const input = await openSearch()
      expect(scrollIntoView).not.toHaveBeenCalled()
      await userEvent.type(input, 'hello')
      await waitFor(() => expect(document.getElementById('current-search-match')).toHaveAttribute('data-match-idx', '0'))
      await waitFor(() => expect(scrolled.at(-1)).toBe(document.getElementById('current-search-match')))
      expect(scrollIntoView).toHaveBeenLastCalledWith({ behavior: 'smooth', block: 'center' })
      const first = scrolled.at(-1)
      const beforeNext = scrollIntoView.mock.calls.length
      fireEvent.keyDown(input, { key: 'Enter' })
      await waitFor(() => expect(document.getElementById('current-search-match')).toHaveAttribute('data-match-idx', '1'))
      expect(scrollIntoView.mock.calls.length).toBeGreaterThan(beforeNext)
      expect(scrolled.at(-1)).toBe(document.getElementById('current-search-match'))
      expect(scrolled.at(-1)).not.toBe(first)
      fireEvent.keyDown(input, { key: 'Enter', shiftKey: true })
      await waitFor(() => expect(document.getElementById('current-search-match')).toHaveAttribute('data-match-idx', '0'))
      expect(scrolled.at(-1)).toBe(document.getElementById('current-search-match'))
      await userEvent.clear(input)
      await waitFor(() => expect(document.getElementById('current-search-match')).toBeNull())
      const afterClear = scrollIntoView.mock.calls.length
      await userEvent.type(input, 'absent')
      expect(document.getElementById('current-search-match')).toBeNull()
      expect(scrollIntoView).toHaveBeenCalledTimes(afterClear)
      fireEvent.keyDown(input, { key: 'Escape' })
      expect(screen.queryByPlaceholderText('Search in file...')).not.toBeInTheDocument()
      expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('/files/read?'))).toHaveLength(1)
    } finally {
      if (previous) Object.defineProperty(Element.prototype, 'scrollIntoView', previous)
      else Reflect.deleteProperty(Element.prototype, 'scrollIntoView')
    }
  })

  it('keeps search navigation usable when the browser DOM has no scrolling method', async () => {
    const input = await openSearch()
    await userEvent.type(input, 'hello')
    await waitFor(() => expect(document.getElementById('current-search-match')).toHaveAttribute('data-match-idx', '0'))
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(document.getElementById('current-search-match')).toHaveAttribute('data-match-idx', '1'))
    fireEvent.keyDown(input, { key: 'Enter', shiftKey: true })
    await waitFor(() => expect(document.getElementById('current-search-match')).toHaveAttribute('data-match-idx', '0'))
  })
})
