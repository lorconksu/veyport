import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ServerDetailPage } from '../server-detail'
import type { User } from '@/types/api'

const auth = vi.hoisted(() => ({ user: { id: 'u1', role: 'admin' } as User | null }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: auth.user }) }))
vi.mock('@/components/server-terminal', () => ({ ServerTerminal: () => null, OfflineTerminalState: () => null }))

// The page, Dropzone, query cache, apiFetch and CSRF cookie lookup run together.
// Only the HTTP boundary and unrelated auth/terminal services are replaced.
const fetchMock = vi.fn<typeof fetch>()
const filename = '<img src=x> café & #?.tar.gz'
const storedFile = { name: filename, path: `/tmp/veyport-dropzone/${filename}`, is_dir: false, readable: true, size: 7 }
let client: QueryClient
let router: ReturnType<typeof createMemoryRouter>
let files: typeof storedFile[]
let mutate: (url: string, options: RequestInit) => Promise<Response>

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function mutationCalls(method: string) {
  return fetchMock.mock.calls.filter(([, options]) => options?.method === method)
}

function listingCalls(serverId = 'srv-1') {
  return fetchMock.mock.calls.filter(([url, options]) => url === `/api/servers/${serverId}/dropzone` && !options?.method)
}

function uploadInput() {
  return screen.getByLabelText('Upload files by clicking or dragging').querySelector('input')!
}

async function renderPage(expand = true) {
  router = createMemoryRouter([{ path: '/servers/:id', element: <ServerDetailPage /> }], {
    initialEntries: ['/servers/srv-2', '/servers/srv-1'],
    initialIndex: 1,
  })
  const view = render(
    <QueryClientProvider client={client}><RouterProvider router={router} /></QueryClientProvider>,
  )
  await screen.findByText('Server srv-1')
  if (expand) {
    await userEvent.click(screen.getByRole('button', { name: 'Dropzone' }))
    await waitFor(() => expect(listingCalls()).toHaveLength(1))
  }
  return view
}

async function finish(action: () => void) {
  await act(async () => { action() })
}

beforeEach(() => {
  auth.user = { id: 'u1', role: 'admin' } as User
  files = []
  sessionStorage.clear()
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } } })
  // A previously visited destination must not introduce a loading unmount that
  // would hide state retained when React reuses the server-detail route.
  client.setQueryData(['server', 'srv-2'], { id: 'srv-2', name: 'Server srv-2', status: 'online', hostname: 'two', labels: '' })
  mutate = async (url) => { throw new Error(`Unexpected mutation: ${url}`) }
  vi.spyOn(document, 'cookie', 'get').mockReturnValue('other=value; __Host-veyport_csrf=dropzone-csrf')
  vi.stubGlobal('fetch', fetchMock.mockReset().mockImplementation(async (input, options = {}) => {
    const url = String(input)
    if (options.method) return mutate(url, options)
    if (url === '/api/servers/reenroll/pending') return json([])
    if (/^\/api\/servers\/srv-[12]$/.test(url)) {
      const id = url.split('/').at(-1)!
      return json({ id, name: `Server ${id}`, status: 'online', hostname: id, labels: '' })
    }
    if (url.endsWith('/my-paths')) return json({ paths: [] })
    if (url.endsWith('/dropzone')) return json({ files: url.includes('srv-1') ? files : [] })
    throw new Error(`Unexpected request: ${url}`)
  }))
})

afterEach(() => {
  cleanup()
  client.clear()
  router?.dispose()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('Dropzone upload through the server detail page', () => {
  it('lazily lists files, opens the picker and uploads the exact multipart file with cookie credentials', async () => {
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await renderPage(false)
    expect(listingCalls()).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Dropzone' }))
    expect(await screen.findByText('No files in dropzone')).toBeInTheDocument()
    const picker = vi.spyOn(uploadInput(), 'click')
    await userEvent.click(screen.getByLabelText('Upload files by clicking or dragging'))
    expect(picker).toHaveBeenCalled()
    const file = new File(['payload'], filename, { type: 'application/gzip' })
    await userEvent.upload(uploadInput(), file)
    expect(screen.getByText('Uploading...')).toBeInTheDocument()
    expect(uploadInput()).toBeDisabled()
    expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeDisabled()
    expect(uploadInput().value).toBe('')
    const [[url, options]] = mutationCalls('POST')
    expect(url).toBe('/api/servers/srv-1/upload')
    expect(options!.credentials).toBe('same-origin')
    const headers = new Headers(options!.headers)
    expect(headers.get('X-CSRF-Token')).toBe('dropzone-csrf')
    expect(headers.get('Content-Type')).toBeNull() // Browser supplies the multipart boundary.
    const body = options!.body as FormData
    expect(body).toBeInstanceOf(FormData)
    expect([...body.keys()]).toEqual(['file'])
    expect(body.get('file')).toBe(file)
    expect(body.get('file')).toMatchObject({ name: filename, size: 7, type: 'application/gzip' })
    files = [storedFile]
    await finish(() => pending.resolve(json({ filename, size: 7 })))
    expect(await screen.findByText(/uploaded successfully/)).toHaveTextContent(`${filename} uploaded successfully (7 B)`)
    await waitFor(() => expect(listingCalls()).toHaveLength(2))
    expect(await screen.findByRole('cell', { name: filename })).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    expect(uploadInput()).toBeEnabled()
  })

  it('accepts only the first dropped file, handles drag feedback, and ignores an empty drop or cancelled picker', async () => {
    mutate = async () => json({ filename: 'first.txt', size: 1 })
    await renderPage()
    const target = screen.getByLabelText('Upload files by clicking or dragging')
    const over = new Event('dragover', { bubbles: true, cancelable: true })
    fireEvent(target, over)
    expect(over.defaultPrevented).toBe(true)
    expect(target).toHaveClass('border-accent')
    fireEvent.dragLeave(target)
    expect(target).not.toHaveClass('border-accent')
    fireEvent.drop(target, { dataTransfer: { files: [] } })
    fireEvent.change(uploadInput(), { target: { files: [] } })
    expect(mutationCalls('POST')).toHaveLength(0)
    const first = new File(['1'], 'first.txt')
    const drop = new Event('drop', { bubbles: true, cancelable: true })
    Object.defineProperty(drop, 'dataTransfer', { value: { files: [first, new File(['2'], 'second.txt')] } })
    fireEvent(target, drop)
    expect(drop.defaultPrevented).toBe(true)
    expect(target).not.toHaveClass('border-accent')
    expect(await screen.findByText(/uploaded successfully/)).toBeInTheDocument()
    expect(mutationCalls('POST')).toHaveLength(1)
    expect((mutationCalls('POST')[0][1]!.body as FormData).get('file')).toBe(first)
  })

  it('suppresses another drop while an upload is pending', async () => {
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await renderPage()
    await userEvent.upload(uploadInput(), new File(['first'], 'first.txt'))
    const target = screen.getByLabelText('Upload files by clicking or dragging')
    expect(target).toBeDisabled()
    // Disabled buttons suppress clicks, but browser drag/drop events still arrive.
    fireEvent.drop(target, { dataTransfer: { files: [new File(['second'], 'second.txt')] } })
    expect(mutationCalls('POST')).toHaveLength(1)
    await finish(() => pending.resolve(json({ filename: 'first.txt', size: 5 })))
    expect(await screen.findByText(/uploaded successfully/)).toHaveTextContent('first.txt')
  })

  it.each([
    ['network Error', () => Promise.reject(new Error('<img src=x> upload unavailable')), '<img src=x> upload unavailable'],
    ['non-Error rejection', () => Promise.reject('network failed'), 'Upload failed'],
    ['HTTP error', async () => json({ error: 'Agent upload timeout' }, 504), 'Agent upload timeout'],
  ])('shows a %s and permits retrying the same file', async (_label, reject, message) => {
    mutate = reject
    await renderPage()
    const file = new File(['retry'], 'retry.txt')
    await userEvent.upload(uploadInput(), file)
    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    expect(uploadInput()).toBeEnabled()
    expect(uploadInput().value).toBe('')
    expect(listingCalls()).toHaveLength(1)
    const retry = deferred<Response>()
    mutate = () => retry.promise
    await userEvent.upload(uploadInput(), file)
    expect(screen.queryByText(message)).not.toBeInTheDocument()
    expect(screen.getByText('Uploading...')).toBeInTheDocument()
    expect(mutationCalls('POST')).toHaveLength(2)
    expect((mutationCalls('POST')[1][1]!.body as FormData).get('file')).toBe(file)
    await finish(() => retry.resolve(json({ filename: 'retry.txt', size: 5 })))
    expect(await screen.findByText(/uploaded successfully/)).toHaveTextContent('retry.txt')
    await waitFor(() => expect(listingCalls()).toHaveLength(2))
  })

  it('clears the prior upload result when a new upload starts', async () => {
    mutate = async () => json({ filename: 'old.txt', size: 1 })
    await renderPage()
    await userEvent.upload(uploadInput(), new File(['1'], 'old.txt'))
    await screen.findByText(/uploaded successfully/)
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await userEvent.upload(uploadInput(), new File(['2'], 'new.txt'))
    expect(screen.queryByText(/uploaded successfully/)).not.toBeInTheDocument()
    await finish(() => pending.reject(new Error('Second upload failed')))
    expect(await screen.findByText('Second upload failed')).toBeInTheDocument()
    expect(screen.queryByText(/uploaded successfully/)).not.toBeInTheDocument()
  })
})

describe('Dropzone deletion through the server detail page', () => {
  it('requires confirmation, cancels without a request, then deletes the encoded literal filename and refreshes the list', async () => {
    files = [storedFile]
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await renderPage()
    await userEvent.click(await screen.findByTitle('Delete file'))
    expect(screen.getByText('Delete File?')).toBeInTheDocument()
    expect(screen.getByText(/Are you sure/)).toHaveTextContent(filename)
    expect(document.querySelector('img')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByText('Delete File?')).not.toBeInTheDocument()
    expect(mutationCalls('DELETE')).toHaveLength(0)
    await userEvent.click(screen.getByTitle('Delete file'))
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(screen.getByText('Deleting File...')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    const close = screen.getByRole('button', { name: 'Close' })
    expect(close).toBeDisabled()
    await userEvent.click(close)
    expect(screen.getByText('Deleting File...')).toBeInTheDocument()
    const [[url, options]] = mutationCalls('DELETE')
    expect(url).toBe(`/api/servers/srv-1/dropzone?filename=${encodeURIComponent(filename)}`)
    expect(options!.credentials).toBe('same-origin')
    expect(new Headers(options!.headers).get('X-CSRF-Token')).toBe('dropzone-csrf')
    expect(options!.body).toBeUndefined()
    files = []
    await finish(() => pending.resolve(new Response(null, { status: 204 })))
    expect(await screen.findByText('File Deleted')).toBeInTheDocument()
    expect(screen.getByText(/has been deleted/)).toHaveTextContent(filename)
    await waitFor(() => expect(listingCalls()).toHaveLength(2))
    expect(await screen.findByText('No files in dropzone')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(screen.queryByText('File Deleted')).not.toBeInTheDocument()
    expect(mutationCalls('DELETE')).toHaveLength(1)
  })

  it.each([
    ['Error', new Error('<img src=x> delete denied'), '<img src=x> delete denied'],
    ['non-Error', 'delete rejected', 'Delete failed'],
  ])('shows an %s failure and retries only the confirmed file', async (_label, error, message) => {
    files = [storedFile]
    mutate = async () => { throw error }
    await renderPage()
    await userEvent.click(await screen.findByTitle('Delete file'))
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByText('Delete Failed')).toBeInTheDocument()
    expect(screen.getByText(message)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    expect(listingCalls()).toHaveLength(1)
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(screen.queryByText(message)).not.toBeInTheDocument()
    expect(screen.getByText('Deleting File...')).toBeInTheDocument()
    expect(mutationCalls('DELETE').map(([url]) => url)).toEqual(Array(2).fill(`/api/servers/srv-1/dropzone?filename=${encodeURIComponent(filename)}`))
    files = []
    await finish(() => pending.resolve(new Response(null, { status: 204 })))
    expect(await screen.findByText('File Deleted')).toBeInTheDocument()
    await waitFor(() => expect(listingCalls()).toHaveLength(2))
  })

  it('closes a deletion error and opens a fresh confirmation for another file', async () => {
    files = [storedFile, { ...storedFile, name: 'another.txt', path: '/tmp/veyport-dropzone/another.txt' }]
    mutate = async () => json({ error: 'Delete unavailable' }, 500)
    await renderPage()
    await userEvent.click(within(await screen.findByRole('row', { name: new RegExp('café') })).getByTitle('Delete file'))
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await screen.findByText('Delete Failed')
    await userEvent.click(screen.getByRole('button', { name: 'Close' }))
    await userEvent.click(within(screen.getByRole('row', { name: /another.txt/ })).getByTitle('Delete file'))
    expect(screen.getByText('Delete File?')).toBeInTheDocument()
    expect(screen.getByText(/Are you sure/)).toHaveTextContent('another.txt')
    expect(screen.queryByText('Delete unavailable')).not.toBeInTheDocument()
  })
})

describe('Dropzone lifecycle and authorization visibility', () => {
  it.each([
    ['ordinary user', { id: 'u1', role: 'user' }],
    ['admin without the authoritative capability', { id: 'u1', role: 'admin', capabilities: [] }],
  ])('does not expose or fetch Dropzone for an %s', async (_label, user) => {
    auth.user = user as User
    await renderPage(false)
    expect(screen.queryByRole('button', { name: 'Dropzone' })).not.toBeInTheDocument()
    expect(listingCalls()).toHaveLength(0)
    expect(mutationCalls('POST')).toHaveLength(0)
    expect(mutationCalls('DELETE')).toHaveLength(0)
  })

  it('shows Dropzone for the explicit operations.admin capability', async () => {
    auth.user = { id: 'u1', role: 'user', capabilities: ['operations.admin'] } as User
    await renderPage()
    expect(screen.getByLabelText('Upload files by clicking or dragging')).toBeInTheDocument()
  })

  it.each(['success', 'error'] as const)('isolates a pending upload %s when navigating to a cached server', async outcome => {
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await renderPage()
    await userEvent.upload(uploadInput(), new File(['old'], 'old-server.txt'))
    // Browser Back can navigate even while a delete overlay is open.
    await act(async () => { await router.navigate(-1) })
    await screen.findByText('Server srv-2')
    expect(screen.queryByText('Uploading...')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Dropzone' }))
    expect(uploadInput()).toBeEnabled()
    await finish(() => outcome === 'success' ? pending.resolve(json({ filename: 'old-server.txt', size: 3 })) : pending.reject(new Error('Old server upload failed')))
    expect(screen.queryByText(/uploaded successfully|Old server upload failed/)).not.toBeInTheDocument()
    expect(client.getQueryState(['dropzone', 'srv-1'])!.isInvalidated).toBe(outcome === 'success')
    expect(client.getQueryState(['dropzone', 'srv-2'])!.isInvalidated).toBe(false)
    expect(listingCalls('srv-2')).toHaveLength(1)
    expect(mutationCalls('POST')).toHaveLength(1)
  })

  it('discards an old server delete confirmation before it can target the next server', async () => {
    files = [storedFile]
    await renderPage()
    await userEvent.click(await screen.findByTitle('Delete file'))
    // Browser Back can navigate even while a delete overlay is open.
    await act(async () => { await router.navigate(-1) })
    await screen.findByText('Server srv-2')
    expect(screen.queryByText('Delete File?')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    expect(mutationCalls('DELETE')).toHaveLength(0)
  })

  it.each(['success', 'error'] as const)('isolates a pending delete %s when navigating to a cached server', async outcome => {
    files = [storedFile]
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await renderPage()
    await userEvent.click(await screen.findByTitle('Delete file'))
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    // Browser Back can navigate even while a delete overlay is open.
    await act(async () => { await router.navigate(-1) })
    await screen.findByText('Server srv-2')
    expect(screen.queryByText('Deleting File...')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Dropzone' }))
    await finish(() => outcome === 'success' ? pending.resolve(new Response(null, { status: 204 })) : pending.reject(new Error('Old server delete failed')))
    expect(screen.queryByText(/File Deleted|Delete Failed|Old server delete failed/)).not.toBeInTheDocument()
    expect(client.getQueryState(['dropzone', 'srv-1'])!.isInvalidated).toBe(outcome === 'success')
    expect(client.getQueryState(['dropzone', 'srv-2'])!.isInvalidated).toBe(false)
    expect(listingCalls('srv-2')).toHaveLength(1)
    expect(mutationCalls('DELETE')).toHaveLength(1)
    expect(mutationCalls('DELETE')[0][0]).toContain('/srv-1/')
  })

  it('keeps a collapsed in-flight upload on its original server and refreshes the list on reopening', async () => {
    const pending = deferred<Response>()
    mutate = () => pending.promise
    await renderPage()
    await userEvent.upload(uploadInput(), new File(['old'], filename))
    await userEvent.click(screen.getByRole('button', { name: 'Dropzone' }))
    expect(screen.queryByText('Uploading...')).not.toBeInTheDocument()
    files = [storedFile]
    await finish(() => pending.resolve(json({ filename, size: 7 })))
    expect(listingCalls()).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Dropzone' }))
    expect(await screen.findByText(/uploaded successfully/)).toHaveTextContent(filename)
    expect(await screen.findByRole('cell', { name: filename })).toBeInTheDocument()
    expect(listingCalls()).toHaveLength(2)
  })
})
